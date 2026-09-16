rule TTP_XOR_WriteProcessMemory_a6a2 {
  strings:
    $key_a6a2 = { f1 d0 [2] c3 f2 [2] c5 c7 [2] eb c7 [2] d4 db }

  condition:
    any of them
}