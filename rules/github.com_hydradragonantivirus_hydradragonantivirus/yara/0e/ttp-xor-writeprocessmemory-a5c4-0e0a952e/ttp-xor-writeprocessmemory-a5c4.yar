rule TTP_XOR_WriteProcessMemory_a5c4 {
  strings:
    $key_a5c4 = { f2 b6 [2] c0 94 [2] c6 a1 [2] e8 a1 [2] d7 bd }

  condition:
    any of them
}