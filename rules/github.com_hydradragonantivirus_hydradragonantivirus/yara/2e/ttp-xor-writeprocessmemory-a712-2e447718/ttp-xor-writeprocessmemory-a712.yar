rule TTP_XOR_WriteProcessMemory_a712 {
  strings:
    $key_a712 = { f0 60 [2] c2 42 [2] c4 77 [2] ea 77 [2] d5 6b }

  condition:
    any of them
}