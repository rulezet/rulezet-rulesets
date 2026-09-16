rule TTP_XOR_WriteProcessMemory_d882 {
  strings:
    $key_d882 = { 8f f0 [2] bd d2 [2] bb e7 [2] 95 e7 [2] aa fb }

  condition:
    any of them
}