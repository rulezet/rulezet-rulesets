rule TTP_XOR_WriteProcessMemory_d2a4 {
  strings:
    $key_d2a4 = { 85 d6 [2] b7 f4 [2] b1 c1 [2] 9f c1 [2] a0 dd }

  condition:
    any of them
}