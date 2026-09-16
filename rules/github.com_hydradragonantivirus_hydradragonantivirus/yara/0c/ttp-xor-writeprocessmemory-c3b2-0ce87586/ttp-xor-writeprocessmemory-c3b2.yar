rule TTP_XOR_WriteProcessMemory_c3b2 {
  strings:
    $key_c3b2 = { 94 c0 [2] a6 e2 [2] a0 d7 [2] 8e d7 [2] b1 cb }

  condition:
    any of them
}