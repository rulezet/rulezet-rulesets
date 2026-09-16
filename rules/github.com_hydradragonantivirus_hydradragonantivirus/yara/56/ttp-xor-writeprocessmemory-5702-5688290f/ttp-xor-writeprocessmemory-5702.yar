rule TTP_XOR_WriteProcessMemory_5702 {
  strings:
    $key_5702 = { 00 70 [2] 32 52 [2] 34 67 [2] 1a 67 [2] 25 7b }

  condition:
    any of them
}