rule TTP_XOR_WriteProcessMemory_a4b4 {
  strings:
    $key_a4b4 = { f3 c6 [2] c1 e4 [2] c7 d1 [2] e9 d1 [2] d6 cd }

  condition:
    any of them
}