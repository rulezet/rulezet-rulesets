rule TTP_XOR_WriteProcessMemory_12f3 {
  strings:
    $key_12f3 = { 45 81 [2] 77 a3 [2] 71 96 [2] 5f 96 [2] 60 8a }

  condition:
    any of them
}