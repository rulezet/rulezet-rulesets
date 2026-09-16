rule TTP_XOR_WriteProcessMemory_b7d3 {
  strings:
    $key_b7d3 = { e0 a1 [2] d2 83 [2] d4 b6 [2] fa b6 [2] c5 aa }

  condition:
    any of them
}