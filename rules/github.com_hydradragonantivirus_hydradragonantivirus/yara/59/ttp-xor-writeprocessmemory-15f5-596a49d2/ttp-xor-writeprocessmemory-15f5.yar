rule TTP_XOR_WriteProcessMemory_15f5 {
  strings:
    $key_15f5 = { 42 87 [2] 70 a5 [2] 76 90 [2] 58 90 [2] 67 8c }

  condition:
    any of them
}