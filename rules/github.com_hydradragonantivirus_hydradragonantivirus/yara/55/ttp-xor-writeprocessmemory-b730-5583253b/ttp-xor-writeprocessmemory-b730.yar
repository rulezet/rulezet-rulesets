rule TTP_XOR_WriteProcessMemory_b730 {
  strings:
    $key_b730 = { e0 42 [2] d2 60 [2] d4 55 [2] fa 55 [2] c5 49 }

  condition:
    any of them
}