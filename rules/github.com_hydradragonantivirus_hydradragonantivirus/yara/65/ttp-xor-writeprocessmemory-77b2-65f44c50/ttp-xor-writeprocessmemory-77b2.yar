rule TTP_XOR_WriteProcessMemory_77b2 {
  strings:
    $key_77b2 = { 20 c0 [2] 12 e2 [2] 14 d7 [2] 3a d7 [2] 05 cb }

  condition:
    any of them
}