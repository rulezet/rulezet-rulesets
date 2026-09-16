rule TTP_XOR_WriteProcessMemory_31b2 {
  strings:
    $key_31b2 = { 66 c0 [2] 54 e2 [2] 52 d7 [2] 7c d7 [2] 43 cb }

  condition:
    any of them
}