rule TTP_XOR_WriteProcessMemory_2cb2 {
  strings:
    $key_2cb2 = { 7b c0 [2] 49 e2 [2] 4f d7 [2] 61 d7 [2] 5e cb }

  condition:
    any of them
}