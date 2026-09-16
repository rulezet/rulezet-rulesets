rule TTP_XOR_WriteProcessMemory_5745 {
  strings:
    $key_5745 = { 00 37 [2] 32 15 [2] 34 20 [2] 1a 20 [2] 25 3c }

  condition:
    any of them
}