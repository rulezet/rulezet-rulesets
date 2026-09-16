rule TTP_XOR_WriteProcessMemory_7863 {
  strings:
    $key_7863 = { 2f 11 [2] 1d 33 [2] 1b 06 [2] 35 06 [2] 0a 1a }

  condition:
    any of them
}