rule TTP_XOR_WriteProcessMemory_7b12 {
  strings:
    $key_7b12 = { 2c 60 [2] 1e 42 [2] 18 77 [2] 36 77 [2] 09 6b }

  condition:
    any of them
}