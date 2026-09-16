rule TTP_XOR_WriteProcessMemory_1ae2 {
  strings:
    $key_1ae2 = { 4d 90 [2] 7f b2 [2] 79 87 [2] 57 87 [2] 68 9b }

  condition:
    any of them
}