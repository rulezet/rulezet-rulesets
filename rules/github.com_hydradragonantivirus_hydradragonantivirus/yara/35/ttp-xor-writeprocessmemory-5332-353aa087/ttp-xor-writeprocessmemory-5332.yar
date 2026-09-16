rule TTP_XOR_WriteProcessMemory_5332 {
  strings:
    $key_5332 = { 04 40 [2] 36 62 [2] 30 57 [2] 1e 57 [2] 21 4b }

  condition:
    any of them
}