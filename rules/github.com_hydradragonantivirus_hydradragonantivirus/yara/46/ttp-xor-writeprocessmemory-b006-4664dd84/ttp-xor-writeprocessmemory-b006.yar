rule TTP_XOR_WriteProcessMemory_b006 {
  strings:
    $key_b006 = { e7 74 [2] d5 56 [2] d3 63 [2] fd 63 [2] c2 7f }

  condition:
    any of them
}