rule TTP_XOR_WriteProcessMemory_1863 {
  strings:
    $key_1863 = { 4f 11 [2] 7d 33 [2] 7b 06 [2] 55 06 [2] 6a 1a }

  condition:
    any of them
}