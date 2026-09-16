rule TTP_XOR_WriteProcessMemory_a768 {
  strings:
    $key_a768 = { f0 1a [2] c2 38 [2] c4 0d [2] ea 0d [2] d5 11 }

  condition:
    any of them
}