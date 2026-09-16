rule TTP_XOR_WriteProcessMemory_a5a5 {
  strings:
    $key_a5a5 = { f2 d7 [2] c0 f5 [2] c6 c0 [2] e8 c0 [2] d7 dc }

  condition:
    any of them
}