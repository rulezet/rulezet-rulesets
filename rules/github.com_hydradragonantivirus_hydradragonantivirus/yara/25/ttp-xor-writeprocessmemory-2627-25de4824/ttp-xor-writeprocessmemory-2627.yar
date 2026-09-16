rule TTP_XOR_WriteProcessMemory_2627 {
  strings:
    $key_2627 = { 71 55 [2] 43 77 [2] 45 42 [2] 6b 42 [2] 54 5e }

  condition:
    any of them
}