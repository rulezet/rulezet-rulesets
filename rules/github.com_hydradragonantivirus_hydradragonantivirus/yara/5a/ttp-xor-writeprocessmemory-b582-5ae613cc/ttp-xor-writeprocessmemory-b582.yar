rule TTP_XOR_WriteProcessMemory_b582 {
  strings:
    $key_b582 = { e2 f0 [2] d0 d2 [2] d6 e7 [2] f8 e7 [2] c7 fb }

  condition:
    any of them
}