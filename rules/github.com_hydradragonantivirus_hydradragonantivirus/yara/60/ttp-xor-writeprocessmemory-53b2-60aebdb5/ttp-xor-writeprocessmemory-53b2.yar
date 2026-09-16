rule TTP_XOR_WriteProcessMemory_53b2 {
  strings:
    $key_53b2 = { 04 c0 [2] 36 e2 [2] 30 d7 [2] 1e d7 [2] 21 cb }

  condition:
    any of them
}