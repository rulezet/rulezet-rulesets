rule TTP_XOR_WriteProcessMemory_4d25 {
  strings:
    $key_4d25 = { 1a 57 [2] 28 75 [2] 2e 40 [2] 00 40 [2] 3f 5c }

  condition:
    any of them
}