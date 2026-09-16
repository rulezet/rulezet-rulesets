rule TTP_XOR_WriteProcessMemory_a732 {
  strings:
    $key_a732 = { f0 40 [2] c2 62 [2] c4 57 [2] ea 57 [2] d5 4b }

  condition:
    any of them
}