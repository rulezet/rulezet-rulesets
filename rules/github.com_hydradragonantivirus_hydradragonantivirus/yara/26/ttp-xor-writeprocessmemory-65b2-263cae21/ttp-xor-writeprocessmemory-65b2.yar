rule TTP_XOR_WriteProcessMemory_65b2 {
  strings:
    $key_65b2 = { 32 c0 [2] 00 e2 [2] 06 d7 [2] 28 d7 [2] 17 cb }

  condition:
    any of them
}