rule TTP_XOR_WriteProcessMemory_15c4 {
  strings:
    $key_15c4 = { 42 b6 [2] 70 94 [2] 76 a1 [2] 58 a1 [2] 67 bd }

  condition:
    any of them
}