rule TTP_XOR_WriteProcessMemory_6b12 {
  strings:
    $key_6b12 = { 3c 60 [2] 0e 42 [2] 08 77 [2] 26 77 [2] 19 6b }

  condition:
    any of them
}