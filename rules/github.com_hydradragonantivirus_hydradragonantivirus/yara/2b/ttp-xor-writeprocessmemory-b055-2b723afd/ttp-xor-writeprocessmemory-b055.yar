rule TTP_XOR_WriteProcessMemory_b055 {
  strings:
    $key_b055 = { e7 27 [2] d5 05 [2] d3 30 [2] fd 30 [2] c2 2c }

  condition:
    any of them
}