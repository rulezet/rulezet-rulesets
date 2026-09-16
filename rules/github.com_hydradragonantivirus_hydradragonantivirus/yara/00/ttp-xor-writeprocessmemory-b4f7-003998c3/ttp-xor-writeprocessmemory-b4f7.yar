rule TTP_XOR_WriteProcessMemory_b4f7 {
  strings:
    $key_b4f7 = { e3 85 [2] d1 a7 [2] d7 92 [2] f9 92 [2] c6 8e }

  condition:
    any of them
}