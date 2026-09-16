rule TTP_XOR_WriteProcessMemory_a5c5 {
  strings:
    $key_a5c5 = { f2 b7 [2] c0 95 [2] c6 a0 [2] e8 a0 [2] d7 bc }

  condition:
    any of them
}