rule TTP_XOR_WriteProcessMemory_7512 {
  strings:
    $key_7512 = { 22 60 [2] 10 42 [2] 16 77 [2] 38 77 [2] 07 6b }

  condition:
    any of them
}