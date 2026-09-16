rule TTP_XOR_WriteProcessMemory_15f3 {
  strings:
    $key_15f3 = { 42 81 [2] 70 a3 [2] 76 96 [2] 58 96 [2] 67 8a }

  condition:
    any of them
}