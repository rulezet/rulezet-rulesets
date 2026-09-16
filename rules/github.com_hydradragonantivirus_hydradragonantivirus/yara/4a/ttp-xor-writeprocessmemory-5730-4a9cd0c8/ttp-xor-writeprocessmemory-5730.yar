rule TTP_XOR_WriteProcessMemory_5730 {
  strings:
    $key_5730 = { 00 42 [2] 32 60 [2] 34 55 [2] 1a 55 [2] 25 49 }

  condition:
    any of them
}