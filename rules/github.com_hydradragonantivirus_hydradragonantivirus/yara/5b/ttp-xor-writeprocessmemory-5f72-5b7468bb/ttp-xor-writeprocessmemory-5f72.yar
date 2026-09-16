rule TTP_XOR_WriteProcessMemory_5f72 {
  strings:
    $key_5f72 = { 08 00 [2] 3a 22 [2] 3c 17 [2] 12 17 [2] 2d 0b }

  condition:
    any of them
}