rule TTP_XOR_WriteProcessMemory_03b2 {
  strings:
    $key_03b2 = { 54 c0 [2] 66 e2 [2] 60 d7 [2] 4e d7 [2] 71 cb }

  condition:
    any of them
}