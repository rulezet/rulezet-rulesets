rule TTP_XOR_WriteProcessMemory_d884 {
  strings:
    $key_d884 = { 8f f6 [2] bd d4 [2] bb e1 [2] 95 e1 [2] aa fd }

  condition:
    any of them
}