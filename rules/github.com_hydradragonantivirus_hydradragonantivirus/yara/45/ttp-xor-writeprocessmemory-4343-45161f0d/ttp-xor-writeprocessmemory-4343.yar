rule TTP_XOR_WriteProcessMemory_4343 {
  strings:
    $key_4343 = { 14 31 [2] 26 13 [2] 20 26 [2] 0e 26 [2] 31 3a }

  condition:
    any of them
}