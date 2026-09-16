rule TTP_XOR_WriteProcessMemory_a012 {
  strings:
    $key_a012 = { f7 60 [2] c5 42 [2] c3 77 [2] ed 77 [2] d2 6b }

  condition:
    any of them
}