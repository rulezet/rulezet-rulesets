rule TTP_XOR_WriteProcessMemory_5725 {
  strings:
    $key_5725 = { 00 57 [2] 32 75 [2] 34 40 [2] 1a 40 [2] 25 5c }

  condition:
    any of them
}