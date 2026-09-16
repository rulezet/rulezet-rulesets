rule TTP_XOR_WriteProcessMemory_b581 {
  strings:
    $key_b581 = { e2 f3 [2] d0 d1 [2] d6 e4 [2] f8 e4 [2] c7 f8 }

  condition:
    any of them
}