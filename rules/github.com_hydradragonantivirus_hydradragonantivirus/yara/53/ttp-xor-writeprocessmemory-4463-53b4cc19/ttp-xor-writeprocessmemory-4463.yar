rule TTP_XOR_WriteProcessMemory_4463 {
  strings:
    $key_4463 = { 13 11 [2] 21 33 [2] 27 06 [2] 09 06 [2] 36 1a }

  condition:
    any of them
}