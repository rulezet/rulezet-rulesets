rule TTP_XOR_WriteProcessMemory_2024 {
  strings:
    $key_2024 = { 77 56 [2] 45 74 [2] 43 41 [2] 6d 41 [2] 52 5d }

  condition:
    any of them
}