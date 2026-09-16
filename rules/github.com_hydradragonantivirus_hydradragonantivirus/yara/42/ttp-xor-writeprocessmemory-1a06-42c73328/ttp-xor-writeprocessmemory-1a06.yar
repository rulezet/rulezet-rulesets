rule TTP_XOR_WriteProcessMemory_1a06 {
  strings:
    $key_1a06 = { 4d 74 [2] 7f 56 [2] 79 63 [2] 57 63 [2] 68 7f }

  condition:
    any of them
}