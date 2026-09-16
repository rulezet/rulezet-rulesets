rule TTP_XOR_WriteProcessMemory_2527 {
  strings:
    $key_2527 = { 72 55 [2] 40 77 [2] 46 42 [2] 68 42 [2] 57 5e }

  condition:
    any of them
}