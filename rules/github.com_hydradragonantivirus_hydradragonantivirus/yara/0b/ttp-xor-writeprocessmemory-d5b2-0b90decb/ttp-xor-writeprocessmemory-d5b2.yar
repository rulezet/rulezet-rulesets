rule TTP_XOR_WriteProcessMemory_d5b2 {
  strings:
    $key_d5b2 = { 82 c0 [2] b0 e2 [2] b6 d7 [2] 98 d7 [2] a7 cb }

  condition:
    any of them
}