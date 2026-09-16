rule TTP_XOR_WriteProcessMemory_b051 {
  strings:
    $key_b051 = { e7 23 [2] d5 01 [2] d3 34 [2] fd 34 [2] c2 28 }

  condition:
    any of them
}