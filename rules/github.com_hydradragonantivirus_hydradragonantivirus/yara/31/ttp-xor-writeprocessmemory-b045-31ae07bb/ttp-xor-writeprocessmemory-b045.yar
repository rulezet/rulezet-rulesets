rule TTP_XOR_WriteProcessMemory_b045 {
  strings:
    $key_b045 = { e7 37 [2] d5 15 [2] d3 20 [2] fd 20 [2] c2 3c }

  condition:
    any of them
}