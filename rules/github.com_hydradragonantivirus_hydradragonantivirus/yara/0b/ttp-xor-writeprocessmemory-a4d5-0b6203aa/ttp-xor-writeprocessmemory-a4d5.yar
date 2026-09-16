rule TTP_XOR_WriteProcessMemory_a4d5 {
  strings:
    $key_a4d5 = { f3 a7 [2] c1 85 [2] c7 b0 [2] e9 b0 [2] d6 ac }

  condition:
    any of them
}