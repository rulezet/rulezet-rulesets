rule TTP_XOR_WriteProcessMemory_16d0 {
  strings:
    $key_16d0 = { 41 a2 [2] 73 80 [2] 75 b5 [2] 5b b5 [2] 64 a9 }

  condition:
    any of them
}