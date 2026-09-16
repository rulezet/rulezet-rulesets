rule TTP_XOR_WriteProcessMemory_b1f7 {
  strings:
    $key_b1f7 = { e6 85 [2] d4 a7 [2] d2 92 [2] fc 92 [2] c3 8e }

  condition:
    any of them
}