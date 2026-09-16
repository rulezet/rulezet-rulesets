rule TTP_XOR_WriteProcessMemory_b5a7 {
  strings:
    $key_b5a7 = { e2 d5 [2] d0 f7 [2] d6 c2 [2] f8 c2 [2] c7 de }

  condition:
    any of them
}