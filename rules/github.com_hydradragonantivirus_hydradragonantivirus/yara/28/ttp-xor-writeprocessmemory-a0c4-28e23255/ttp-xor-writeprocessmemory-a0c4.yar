rule TTP_XOR_WriteProcessMemory_a0c4 {
  strings:
    $key_a0c4 = { f7 b6 [2] c5 94 [2] c3 a1 [2] ed a1 [2] d2 bd }

  condition:
    any of them
}