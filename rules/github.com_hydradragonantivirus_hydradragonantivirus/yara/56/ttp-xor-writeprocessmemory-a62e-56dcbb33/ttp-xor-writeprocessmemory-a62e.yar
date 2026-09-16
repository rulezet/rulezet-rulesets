rule TTP_XOR_WriteProcessMemory_a62e {
  strings:
    $key_a62e = { f1 5c [2] c3 7e [2] c5 4b [2] eb 4b [2] d4 57 }

  condition:
    any of them
}