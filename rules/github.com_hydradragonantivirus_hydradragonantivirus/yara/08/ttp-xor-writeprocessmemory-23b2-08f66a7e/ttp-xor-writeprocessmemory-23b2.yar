rule TTP_XOR_WriteProcessMemory_23b2 {
  strings:
    $key_23b2 = { 74 c0 [2] 46 e2 [2] 40 d7 [2] 6e d7 [2] 51 cb }

  condition:
    any of them
}