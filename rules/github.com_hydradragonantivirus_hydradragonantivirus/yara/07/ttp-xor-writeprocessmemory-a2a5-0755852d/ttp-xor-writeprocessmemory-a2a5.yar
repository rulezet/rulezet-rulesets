rule TTP_XOR_WriteProcessMemory_a2a5 {
  strings:
    $key_a2a5 = { f5 d7 [2] c7 f5 [2] c1 c0 [2] ef c0 [2] d0 dc }

  condition:
    any of them
}