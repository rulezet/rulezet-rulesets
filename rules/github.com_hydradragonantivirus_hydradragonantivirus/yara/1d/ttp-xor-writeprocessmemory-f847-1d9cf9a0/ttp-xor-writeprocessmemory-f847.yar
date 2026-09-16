rule TTP_XOR_WriteProcessMemory_f847 {
  strings:
    $key_f847 = { af 35 [2] 9d 17 [2] 9b 22 [2] b5 22 [2] 8a 3e }

  condition:
    any of them
}