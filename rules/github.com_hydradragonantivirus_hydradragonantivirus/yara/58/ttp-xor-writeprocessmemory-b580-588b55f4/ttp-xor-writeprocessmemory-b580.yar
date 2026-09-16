rule TTP_XOR_WriteProcessMemory_b580 {
  strings:
    $key_b580 = { e2 f2 [2] d0 d0 [2] d6 e5 [2] f8 e5 [2] c7 f9 }

  condition:
    any of them
}