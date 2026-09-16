rule TTP_XOR_WriteProcessMemory_74b2 {
  strings:
    $key_74b2 = { 23 c0 [2] 11 e2 [2] 17 d7 [2] 39 d7 [2] 06 cb }

  condition:
    any of them
}