rule TTP_XOR_WriteProcessMemory_7312 {
  strings:
    $key_7312 = { 24 60 [2] 16 42 [2] 10 77 [2] 3e 77 [2] 01 6b }

  condition:
    any of them
}