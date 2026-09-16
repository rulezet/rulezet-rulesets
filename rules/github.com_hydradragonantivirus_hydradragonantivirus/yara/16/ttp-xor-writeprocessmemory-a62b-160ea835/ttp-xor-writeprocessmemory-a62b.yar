rule TTP_XOR_WriteProcessMemory_a62b {
  strings:
    $key_a62b = { f1 59 [2] c3 7b [2] c5 4e [2] eb 4e [2] d4 52 }

  condition:
    any of them
}