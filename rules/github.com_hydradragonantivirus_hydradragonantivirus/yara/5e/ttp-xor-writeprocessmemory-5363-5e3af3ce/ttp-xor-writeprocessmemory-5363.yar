rule TTP_XOR_WriteProcessMemory_5363 {
  strings:
    $key_5363 = { 04 11 [2] 36 33 [2] 30 06 [2] 1e 06 [2] 21 1a }

  condition:
    any of them
}