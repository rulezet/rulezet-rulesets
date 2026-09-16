rule TTP_XOR_WriteProcessMemory_4322 {
  strings:
    $key_4322 = { 14 50 [2] 26 72 [2] 20 47 [2] 0e 47 [2] 31 5b }

  condition:
    any of them
}