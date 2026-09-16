rule TTP_XOR_WriteProcessMemory_b052 {
  strings:
    $key_b052 = { e7 20 [2] d5 02 [2] d3 37 [2] fd 37 [2] c2 2b }

  condition:
    any of them
}