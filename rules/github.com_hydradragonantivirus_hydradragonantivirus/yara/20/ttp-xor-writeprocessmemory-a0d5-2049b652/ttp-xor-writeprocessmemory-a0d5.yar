rule TTP_XOR_WriteProcessMemory_a0d5 {
  strings:
    $key_a0d5 = { f7 a7 [2] c5 85 [2] c3 b0 [2] ed b0 [2] d2 ac }

  condition:
    any of them
}