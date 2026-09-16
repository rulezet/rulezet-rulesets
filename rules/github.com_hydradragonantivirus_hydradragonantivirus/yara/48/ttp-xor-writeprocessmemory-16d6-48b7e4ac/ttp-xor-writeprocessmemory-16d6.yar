rule TTP_XOR_WriteProcessMemory_16d6 {
  strings:
    $key_16d6 = { 41 a4 [2] 73 86 [2] 75 b3 [2] 5b b3 [2] 64 af }

  condition:
    any of them
}