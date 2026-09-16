rule TTP_XOR_WriteProcessMemory_b5c5 {
  strings:
    $key_b5c5 = { e2 b7 [2] d0 95 [2] d6 a0 [2] f8 a0 [2] c7 bc }

  condition:
    any of them
}