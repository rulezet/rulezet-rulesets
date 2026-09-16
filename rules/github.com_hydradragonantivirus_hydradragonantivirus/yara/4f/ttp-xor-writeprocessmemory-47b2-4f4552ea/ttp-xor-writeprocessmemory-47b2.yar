rule TTP_XOR_WriteProcessMemory_47b2 {
  strings:
    $key_47b2 = { 10 c0 [2] 22 e2 [2] 24 d7 [2] 0a d7 [2] 35 cb }

  condition:
    any of them
}