rule TTP_XOR_WriteProcessMemory_a529 {
  strings:
    $key_a529 = { f2 5b [2] c0 79 [2] c6 4c [2] e8 4c [2] d7 50 }

  condition:
    any of them
}