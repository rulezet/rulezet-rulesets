rule TTP_XOR_WriteProcessMemory_b4f1 {
  strings:
    $key_b4f1 = { e3 83 [2] d1 a1 [2] d7 94 [2] f9 94 [2] c6 88 }

  condition:
    any of them
}