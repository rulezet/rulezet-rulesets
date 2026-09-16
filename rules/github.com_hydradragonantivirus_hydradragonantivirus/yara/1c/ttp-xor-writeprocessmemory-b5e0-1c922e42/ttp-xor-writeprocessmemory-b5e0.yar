rule TTP_XOR_WriteProcessMemory_b5e0 {
  strings:
    $key_b5e0 = { e2 92 [2] d0 b0 [2] d6 85 [2] f8 85 [2] c7 99 }

  condition:
    any of them
}