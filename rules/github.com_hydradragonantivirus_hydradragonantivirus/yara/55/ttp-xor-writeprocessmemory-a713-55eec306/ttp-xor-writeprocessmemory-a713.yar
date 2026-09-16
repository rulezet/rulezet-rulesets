rule TTP_XOR_WriteProcessMemory_a713 {
  strings:
    $key_a713 = { f0 61 [2] c2 43 [2] c4 76 [2] ea 76 [2] d5 6a }

  condition:
    any of them
}