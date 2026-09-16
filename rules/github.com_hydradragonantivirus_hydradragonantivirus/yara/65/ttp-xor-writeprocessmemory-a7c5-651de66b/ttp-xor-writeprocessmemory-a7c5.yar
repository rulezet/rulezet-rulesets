rule TTP_XOR_WriteProcessMemory_a7c5 {
  strings:
    $key_a7c5 = { f0 b7 [2] c2 95 [2] c4 a0 [2] ea a0 [2] d5 bc }

  condition:
    any of them
}