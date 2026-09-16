rule TTP_XOR_WriteProcessMemory_5d32 {
  strings:
    $key_5d32 = { 0a 40 [2] 38 62 [2] 3e 57 [2] 10 57 [2] 2f 4b }

  condition:
    any of them
}