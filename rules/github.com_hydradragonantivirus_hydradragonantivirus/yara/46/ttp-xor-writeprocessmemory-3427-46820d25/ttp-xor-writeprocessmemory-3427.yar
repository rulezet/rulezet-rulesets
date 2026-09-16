rule TTP_XOR_WriteProcessMemory_3427 {
  strings:
    $key_3427 = { 63 55 [2] 51 77 [2] 57 42 [2] 79 42 [2] 46 5e }

  condition:
    any of them
}