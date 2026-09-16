rule TTP_XOR_WriteProcessMemory_3cb2 {
  strings:
    $key_3cb2 = { 6b c0 [2] 59 e2 [2] 5f d7 [2] 71 d7 [2] 4e cb }

  condition:
    any of them
}