rule TTP_XOR_WriteProcessMemory_7cb2 {
  strings:
    $key_7cb2 = { 2b c0 [2] 19 e2 [2] 1f d7 [2] 31 d7 [2] 0e cb }

  condition:
    any of them
}