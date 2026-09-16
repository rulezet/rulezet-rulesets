rule TTP_XOR_WriteProcessMemory_a1a3 {
  strings:
    $key_a1a3 = { f6 d1 [2] c4 f3 [2] c2 c6 [2] ec c6 [2] d3 da }

  condition:
    any of them
}