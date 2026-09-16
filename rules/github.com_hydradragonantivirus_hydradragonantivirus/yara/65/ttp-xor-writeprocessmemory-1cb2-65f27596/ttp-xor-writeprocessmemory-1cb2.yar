rule TTP_XOR_WriteProcessMemory_1cb2 {
  strings:
    $key_1cb2 = { 4b c0 [2] 79 e2 [2] 7f d7 [2] 51 d7 [2] 6e cb }

  condition:
    any of them
}