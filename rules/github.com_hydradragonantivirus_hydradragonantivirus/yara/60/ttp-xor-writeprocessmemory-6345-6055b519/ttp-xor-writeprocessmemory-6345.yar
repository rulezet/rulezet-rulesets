rule TTP_XOR_WriteProcessMemory_6345 {
  strings:
    $key_6345 = { 34 37 [2] 06 15 [2] 00 20 [2] 2e 20 [2] 11 3c }

  condition:
    any of them
}