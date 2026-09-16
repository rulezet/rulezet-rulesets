rule TTP_XOR_WriteProcessMemory_11b2 {
  strings:
    $key_11b2 = { 46 c0 [2] 74 e2 [2] 72 d7 [2] 5c d7 [2] 63 cb }

  condition:
    any of them
}