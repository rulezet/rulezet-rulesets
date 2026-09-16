rule TTP_XOR_WriteProcessMemory_5442 {
  strings:
    $key_5442 = { 03 30 [2] 31 12 [2] 37 27 [2] 19 27 [2] 26 3b }

  condition:
    any of them
}