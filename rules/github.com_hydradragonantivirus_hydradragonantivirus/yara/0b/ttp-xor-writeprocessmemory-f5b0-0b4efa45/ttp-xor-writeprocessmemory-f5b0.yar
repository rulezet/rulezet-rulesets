rule TTP_XOR_WriteProcessMemory_f5b0 {
  strings:
    $key_f5b0 = { a2 c2 [2] 90 e0 [2] 96 d5 [2] b8 d5 [2] 87 c9 }

  condition:
    any of them
}