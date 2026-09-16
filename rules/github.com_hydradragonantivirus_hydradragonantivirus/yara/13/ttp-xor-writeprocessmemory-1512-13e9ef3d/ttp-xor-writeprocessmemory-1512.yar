rule TTP_XOR_WriteProcessMemory_1512 {
  strings:
    $key_1512 = { 42 60 [2] 70 42 [2] 76 77 [2] 58 77 [2] 67 6b }

  condition:
    any of them
}