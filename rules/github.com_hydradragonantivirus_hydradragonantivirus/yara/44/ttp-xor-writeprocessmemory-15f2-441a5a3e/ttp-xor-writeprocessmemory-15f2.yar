rule TTP_XOR_WriteProcessMemory_15f2 {
  strings:
    $key_15f2 = { 42 80 [2] 70 a2 [2] 76 97 [2] 58 97 [2] 67 8b }

  condition:
    any of them
}