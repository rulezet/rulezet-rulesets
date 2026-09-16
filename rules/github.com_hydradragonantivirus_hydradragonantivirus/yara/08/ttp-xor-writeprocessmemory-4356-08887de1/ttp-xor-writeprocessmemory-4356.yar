rule TTP_XOR_WriteProcessMemory_4356 {
  strings:
    $key_4356 = { 14 24 [2] 26 06 [2] 20 33 [2] 0e 33 [2] 31 2f }

  condition:
    any of them
}