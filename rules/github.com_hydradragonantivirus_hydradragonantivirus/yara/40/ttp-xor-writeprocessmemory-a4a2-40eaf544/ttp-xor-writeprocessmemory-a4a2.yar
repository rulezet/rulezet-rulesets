rule TTP_XOR_WriteProcessMemory_a4a2 {
  strings:
    $key_a4a2 = { f3 d0 [2] c1 f2 [2] c7 c7 [2] e9 c7 [2] d6 db }

  condition:
    any of them
}