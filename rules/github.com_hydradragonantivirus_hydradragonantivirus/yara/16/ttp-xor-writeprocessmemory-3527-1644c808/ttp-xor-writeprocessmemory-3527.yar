rule TTP_XOR_WriteProcessMemory_3527 {
  strings:
    $key_3527 = { 62 55 [2] 50 77 [2] 56 42 [2] 78 42 [2] 47 5e }

  condition:
    any of them
}