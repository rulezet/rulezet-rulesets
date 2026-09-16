rule TTP_XOR_WriteProcessMemory_5525 {
  strings:
    $key_5525 = { 02 57 [2] 30 75 [2] 36 40 [2] 18 40 [2] 27 5c }

  condition:
    any of them
}