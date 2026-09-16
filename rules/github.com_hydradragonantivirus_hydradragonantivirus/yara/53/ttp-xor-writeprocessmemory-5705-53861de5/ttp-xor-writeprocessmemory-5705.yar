rule TTP_XOR_WriteProcessMemory_5705 {
  strings:
    $key_5705 = { 00 77 [2] 32 55 [2] 34 60 [2] 1a 60 [2] 25 7c }

  condition:
    any of them
}