rule TTP_XOR_WriteProcessMemory_a4d0 {
  strings:
    $key_a4d0 = { f3 a2 [2] c1 80 [2] c7 b5 [2] e9 b5 [2] d6 a9 }

  condition:
    any of them
}