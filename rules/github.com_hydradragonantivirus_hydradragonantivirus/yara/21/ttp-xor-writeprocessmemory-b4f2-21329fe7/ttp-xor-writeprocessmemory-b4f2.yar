rule TTP_XOR_WriteProcessMemory_b4f2 {
  strings:
    $key_b4f2 = { e3 80 [2] d1 a2 [2] d7 97 [2] f9 97 [2] c6 8b }

  condition:
    any of them
}