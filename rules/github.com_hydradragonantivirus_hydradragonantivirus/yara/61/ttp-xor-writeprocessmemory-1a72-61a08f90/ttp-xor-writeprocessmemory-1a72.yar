rule TTP_XOR_WriteProcessMemory_1a72 {
  strings:
    $key_1a72 = { 4d 00 [2] 7f 22 [2] 79 17 [2] 57 17 [2] 68 0b }

  condition:
    any of them
}