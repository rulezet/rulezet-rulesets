rule TTP_XOR_WriteProcessMemory_6525 {
  strings:
    $key_6525 = { 32 57 [2] 00 75 [2] 06 40 [2] 28 40 [2] 17 5c }

  condition:
    any of them
}