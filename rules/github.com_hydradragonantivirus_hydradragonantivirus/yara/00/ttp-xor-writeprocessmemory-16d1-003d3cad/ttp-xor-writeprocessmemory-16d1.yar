rule TTP_XOR_WriteProcessMemory_16d1 {
  strings:
    $key_16d1 = { 41 a3 [2] 73 81 [2] 75 b4 [2] 5b b4 [2] 64 a8 }

  condition:
    any of them
}