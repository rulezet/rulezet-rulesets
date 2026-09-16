rule TTP_XOR_WriteProcessMemory_4732 {
  strings:
    $key_4732 = { 10 40 [2] 22 62 [2] 24 57 [2] 0a 57 [2] 35 4b }

  condition:
    any of them
}