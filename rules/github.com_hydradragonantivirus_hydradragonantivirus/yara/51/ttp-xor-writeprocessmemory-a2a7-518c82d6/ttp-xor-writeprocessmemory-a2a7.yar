rule TTP_XOR_WriteProcessMemory_a2a7 {
  strings:
    $key_a2a7 = { f5 d5 [2] c7 f7 [2] c1 c2 [2] ef c2 [2] d0 de }

  condition:
    any of them
}