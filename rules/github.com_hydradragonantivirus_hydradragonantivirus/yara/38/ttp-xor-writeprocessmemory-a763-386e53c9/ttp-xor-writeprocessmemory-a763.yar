rule TTP_XOR_WriteProcessMemory_a763 {
  strings:
    $key_a763 = { f0 11 [2] c2 33 [2] c4 06 [2] ea 06 [2] d5 1a }

  condition:
    any of them
}