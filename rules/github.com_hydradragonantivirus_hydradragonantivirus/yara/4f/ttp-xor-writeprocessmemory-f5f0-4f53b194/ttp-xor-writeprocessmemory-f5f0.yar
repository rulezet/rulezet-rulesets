rule TTP_XOR_WriteProcessMemory_f5f0 {
  strings:
    $key_f5f0 = { a2 82 [2] 90 a0 [2] 96 95 [2] b8 95 [2] 87 89 }

  condition:
    any of them
}