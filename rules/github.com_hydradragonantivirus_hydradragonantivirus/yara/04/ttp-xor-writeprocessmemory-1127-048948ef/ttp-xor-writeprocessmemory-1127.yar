rule TTP_XOR_WriteProcessMemory_1127 {
  strings:
    $key_1127 = { 46 55 [2] 74 77 [2] 72 42 [2] 5c 42 [2] 63 5e }

  condition:
    any of them
}