rule TTP_XOR_WriteProcessMemory_f5d1 {
  strings:
    $key_f5d1 = { a2 a3 [2] 90 81 [2] 96 b4 [2] b8 b4 [2] 87 a8 }

  condition:
    any of them
}