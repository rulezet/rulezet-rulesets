rule TTP_XOR_WriteProcessMemory_a2b4 {
  strings:
    $key_a2b4 = { f5 c6 [2] c7 e4 [2] c1 d1 [2] ef d1 [2] d0 cd }

  condition:
    any of them
}