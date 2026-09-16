rule TTP_XOR_WriteProcessMemory_4cb2 {
  strings:
    $key_4cb2 = { 1b c0 [2] 29 e2 [2] 2f d7 [2] 01 d7 [2] 3e cb }

  condition:
    any of them
}