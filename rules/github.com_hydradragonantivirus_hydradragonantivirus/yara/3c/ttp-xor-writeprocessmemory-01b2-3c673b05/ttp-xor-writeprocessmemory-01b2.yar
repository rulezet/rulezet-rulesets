rule TTP_XOR_WriteProcessMemory_01b2 {
  strings:
    $key_01b2 = { 56 c0 [2] 64 e2 [2] 62 d7 [2] 4c d7 [2] 73 cb }

  condition:
    any of them
}