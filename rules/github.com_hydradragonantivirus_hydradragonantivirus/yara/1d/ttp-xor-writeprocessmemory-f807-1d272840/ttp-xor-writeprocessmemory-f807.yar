rule TTP_XOR_WriteProcessMemory_f807 {
  strings:
    $key_f807 = { af 75 [2] 9d 57 [2] 9b 62 [2] b5 62 [2] 8a 7e }

  condition:
    any of them
}