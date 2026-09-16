rule TTP_XOR_WriteProcessMemory_26b2 {
  strings:
    $key_26b2 = { 71 c0 [2] 43 e2 [2] 45 d7 [2] 6b d7 [2] 54 cb }

  condition:
    any of them
}