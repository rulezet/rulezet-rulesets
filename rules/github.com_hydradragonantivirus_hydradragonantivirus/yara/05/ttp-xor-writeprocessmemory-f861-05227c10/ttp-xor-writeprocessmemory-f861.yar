rule TTP_XOR_WriteProcessMemory_f861 {
  strings:
    $key_f861 = { af 13 [2] 9d 31 [2] 9b 04 [2] b5 04 [2] 8a 18 }

  condition:
    any of them
}