rule TTP_XOR_WriteProcessMemory_d2b2 {
  strings:
    $key_d2b2 = { 85 c0 [2] b7 e2 [2] b1 d7 [2] 9f d7 [2] a0 cb }

  condition:
    any of them
}