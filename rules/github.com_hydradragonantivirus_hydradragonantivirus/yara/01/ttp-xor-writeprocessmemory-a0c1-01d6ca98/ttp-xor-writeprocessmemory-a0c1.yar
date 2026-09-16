rule TTP_XOR_WriteProcessMemory_a0c1 {
  strings:
    $key_a0c1 = { f7 b3 [2] c5 91 [2] c3 a4 [2] ed a4 [2] d2 b8 }

  condition:
    any of them
}