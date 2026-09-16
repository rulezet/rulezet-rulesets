rule TTP_XOR_WriteProcessMemory_b794 {
  strings:
    $key_b794 = { e0 e6 [2] d2 c4 [2] d4 f1 [2] fa f1 [2] c5 ed }

  condition:
    any of them
}