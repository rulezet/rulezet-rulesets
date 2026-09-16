rule TTP_XOR_WriteProcessMemory_a702 {
  strings:
    $key_a702 = { f0 70 [2] c2 52 [2] c4 67 [2] ea 67 [2] d5 7b }

  condition:
    any of them
}