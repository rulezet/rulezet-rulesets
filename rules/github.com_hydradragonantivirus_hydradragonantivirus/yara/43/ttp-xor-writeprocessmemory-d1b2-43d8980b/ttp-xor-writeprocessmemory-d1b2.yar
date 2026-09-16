rule TTP_XOR_WriteProcessMemory_d1b2 {
  strings:
    $key_d1b2 = { 86 c0 [2] b4 e2 [2] b2 d7 [2] 9c d7 [2] a3 cb }

  condition:
    any of them
}