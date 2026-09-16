rule TTP_XOR_WriteProcessMemory_b0e3 {
  strings:
    $key_b0e3 = { e7 91 [2] d5 b3 [2] d3 86 [2] fd 86 [2] c2 9a }

  condition:
    any of them
}