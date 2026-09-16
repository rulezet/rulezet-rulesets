rule TTP_XOR_WriteProcessMemory_16d2 {
  strings:
    $key_16d2 = { 41 a0 [2] 73 82 [2] 75 b7 [2] 5b b7 [2] 64 ab }

  condition:
    any of them
}