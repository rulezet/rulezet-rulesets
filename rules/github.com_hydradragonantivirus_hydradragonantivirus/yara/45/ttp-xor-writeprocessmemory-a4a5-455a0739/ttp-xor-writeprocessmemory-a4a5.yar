rule TTP_XOR_WriteProcessMemory_a4a5 {
  strings:
    $key_a4a5 = { f3 d7 [2] c1 f5 [2] c7 c0 [2] e9 c0 [2] d6 dc }

  condition:
    any of them
}