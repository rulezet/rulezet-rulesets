rule TTP_XOR_WriteProcessMemory_b070 {
  strings:
    $key_b070 = { e7 02 [2] d5 20 [2] d3 15 [2] fd 15 [2] c2 09 }

  condition:
    any of them
}