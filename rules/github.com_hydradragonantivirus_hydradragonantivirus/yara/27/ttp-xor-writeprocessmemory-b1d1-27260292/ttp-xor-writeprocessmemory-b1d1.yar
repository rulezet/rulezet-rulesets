rule TTP_XOR_WriteProcessMemory_b1d1 {
  strings:
    $key_b1d1 = { e6 a3 [2] d4 81 [2] d2 b4 [2] fc b4 [2] c3 a8 }

  condition:
    any of them
}