rule TTP_XOR_WriteProcessMemory_e4b2 {
  strings:
    $key_e4b2 = { b3 c0 [2] 81 e2 [2] 87 d7 [2] a9 d7 [2] 96 cb }

  condition:
    any of them
}