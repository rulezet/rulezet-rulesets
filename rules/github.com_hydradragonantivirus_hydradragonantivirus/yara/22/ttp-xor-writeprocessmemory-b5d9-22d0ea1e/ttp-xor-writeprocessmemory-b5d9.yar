rule TTP_XOR_WriteProcessMemory_b5d9 {
  strings:
    $key_b5d9 = { e2 ab [2] d0 89 [2] d6 bc [2] f8 bc [2] c7 a0 }

  condition:
    any of them
}