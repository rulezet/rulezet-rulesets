rule TTP_XOR_WriteProcessMemory_d0b2 {
  strings:
    $key_d0b2 = { 87 c0 [2] b5 e2 [2] b3 d7 [2] 9d d7 [2] a2 cb }

  condition:
    any of them
}