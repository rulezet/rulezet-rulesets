rule TTP_XOR_WriteProcessMemory_2b72 {
  strings:
    $key_2b72 = { 7c 00 [2] 4e 22 [2] 48 17 [2] 66 17 [2] 59 0b }

  condition:
    any of them
}