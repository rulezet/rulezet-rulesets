rule TTP_XOR_WriteProcessMemory_b710 {
  strings:
    $key_b710 = { e0 62 [2] d2 40 [2] d4 75 [2] fa 75 [2] c5 69 }

  condition:
    any of them
}