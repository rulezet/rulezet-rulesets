rule TTP_XOR_WriteProcessMemory_25b2 {
  strings:
    $key_25b2 = { 72 c0 [2] 40 e2 [2] 46 d7 [2] 68 d7 [2] 57 cb }

  condition:
    any of them
}