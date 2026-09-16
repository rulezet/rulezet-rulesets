rule TTP_XOR_WriteProcessMemory_1a55 {
  strings:
    $key_1a55 = { 4d 27 [2] 7f 05 [2] 79 30 [2] 57 30 [2] 68 2c }

  condition:
    any of them
}