rule TTP_XOR_WriteProcessMemory_1b12 {
  strings:
    $key_1b12 = { 4c 60 [2] 7e 42 [2] 78 77 [2] 56 77 [2] 69 6b }

  condition:
    any of them
}