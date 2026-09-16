rule TTP_XOR_WriteProcessMemory_b1c1 {
  strings:
    $key_b1c1 = { e6 b3 [2] d4 91 [2] d2 a4 [2] fc a4 [2] c3 b8 }

  condition:
    any of them
}