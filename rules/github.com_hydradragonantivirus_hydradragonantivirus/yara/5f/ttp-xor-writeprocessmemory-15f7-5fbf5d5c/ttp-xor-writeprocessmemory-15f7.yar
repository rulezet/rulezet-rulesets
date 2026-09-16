rule TTP_XOR_WriteProcessMemory_15f7 {
  strings:
    $key_15f7 = { 42 85 [2] 70 a7 [2] 76 92 [2] 58 92 [2] 67 8e }

  condition:
    any of them
}