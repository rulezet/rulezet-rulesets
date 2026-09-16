rule TTP_XOR_WriteProcessMemory_a1a5 {
  strings:
    $key_a1a5 = { f6 d7 [2] c4 f5 [2] c2 c0 [2] ec c0 [2] d3 dc }

  condition:
    any of them
}