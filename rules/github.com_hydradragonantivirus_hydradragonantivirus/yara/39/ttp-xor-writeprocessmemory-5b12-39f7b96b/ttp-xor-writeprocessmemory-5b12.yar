rule TTP_XOR_WriteProcessMemory_5b12 {
  strings:
    $key_5b12 = { 0c 60 [2] 3e 42 [2] 38 77 [2] 16 77 [2] 29 6b }

  condition:
    any of them
}