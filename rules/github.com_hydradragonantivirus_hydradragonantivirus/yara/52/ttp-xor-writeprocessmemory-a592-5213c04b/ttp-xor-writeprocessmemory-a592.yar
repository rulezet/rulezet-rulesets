rule TTP_XOR_WriteProcessMemory_a592 {
  strings:
    $key_a592 = { f2 e0 [2] c0 c2 [2] c6 f7 [2] e8 f7 [2] d7 eb }

  condition:
    any of them
}