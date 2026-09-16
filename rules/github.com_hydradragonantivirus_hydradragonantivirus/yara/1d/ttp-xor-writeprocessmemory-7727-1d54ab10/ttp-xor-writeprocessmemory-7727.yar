rule TTP_XOR_WriteProcessMemory_7727 {
  strings:
    $key_7727 = { 20 55 [2] 12 77 [2] 14 42 [2] 3a 42 [2] 05 5e }

  condition:
    any of them
}