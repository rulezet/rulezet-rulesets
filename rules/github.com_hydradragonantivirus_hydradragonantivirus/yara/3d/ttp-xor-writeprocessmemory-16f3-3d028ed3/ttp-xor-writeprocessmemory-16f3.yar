rule TTP_XOR_WriteProcessMemory_16f3 {
  strings:
    $key_16f3 = { 41 81 [2] 73 a3 [2] 75 96 [2] 5b 96 [2] 64 8a }

  condition:
    any of them
}