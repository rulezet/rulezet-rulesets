rule TTP_XOR_WriteProcessMemory_a497 {
  strings:
    $key_a497 = { f3 e5 [2] c1 c7 [2] c7 f2 [2] e9 f2 [2] d6 ee }

  condition:
    any of them
}