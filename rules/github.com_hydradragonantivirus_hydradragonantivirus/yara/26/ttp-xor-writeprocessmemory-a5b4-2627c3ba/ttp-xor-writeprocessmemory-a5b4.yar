rule TTP_XOR_WriteProcessMemory_a5b4 {
  strings:
    $key_a5b4 = { f2 c6 [2] c0 e4 [2] c6 d1 [2] e8 d1 [2] d7 cd }

  condition:
    any of them
}