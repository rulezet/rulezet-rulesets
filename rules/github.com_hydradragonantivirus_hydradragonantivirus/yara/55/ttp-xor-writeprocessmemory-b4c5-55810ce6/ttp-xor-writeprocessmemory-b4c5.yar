rule TTP_XOR_WriteProcessMemory_b4c5 {
  strings:
    $key_b4c5 = { e3 b7 [2] d1 95 [2] d7 a0 [2] f9 a0 [2] c6 bc }

  condition:
    any of them
}