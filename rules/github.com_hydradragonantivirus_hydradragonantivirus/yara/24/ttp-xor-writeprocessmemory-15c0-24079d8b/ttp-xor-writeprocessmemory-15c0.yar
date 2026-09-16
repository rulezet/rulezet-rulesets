rule TTP_XOR_WriteProcessMemory_15c0 {
  strings:
    $key_15c0 = { 42 b2 [2] 70 90 [2] 76 a5 [2] 58 a5 [2] 67 b9 }

  condition:
    any of them
}