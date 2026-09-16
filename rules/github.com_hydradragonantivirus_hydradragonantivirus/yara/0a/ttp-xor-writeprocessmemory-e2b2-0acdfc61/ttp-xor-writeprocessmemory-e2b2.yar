rule TTP_XOR_WriteProcessMemory_e2b2 {
  strings:
    $key_e2b2 = { b5 c0 [2] 87 e2 [2] 81 d7 [2] af d7 [2] 90 cb }

  condition:
    any of them
}