rule TTP_XOR_WriteProcessMemory_b042 {
  strings:
    $key_b042 = { e7 30 [2] d5 12 [2] d3 27 [2] fd 27 [2] c2 3b }

  condition:
    any of them
}