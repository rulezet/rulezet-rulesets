rule TTP_XOR_WriteProcessMemory_5312 {
  strings:
    $key_5312 = { 04 60 [2] 36 42 [2] 30 77 [2] 1e 77 [2] 21 6b }

  condition:
    any of them
}