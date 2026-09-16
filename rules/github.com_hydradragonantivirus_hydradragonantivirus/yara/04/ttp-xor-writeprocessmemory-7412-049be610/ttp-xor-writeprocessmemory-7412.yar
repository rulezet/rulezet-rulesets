rule TTP_XOR_WriteProcessMemory_7412 {
  strings:
    $key_7412 = { 23 60 [2] 11 42 [2] 17 77 [2] 39 77 [2] 06 6b }

  condition:
    any of them
}