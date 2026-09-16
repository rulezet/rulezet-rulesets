rule TTP_XOR_WriteProcessMemory_a60e {
  strings:
    $key_a60e = { f1 7c [2] c3 5e [2] c5 6b [2] eb 6b [2] d4 77 }

  condition:
    any of them
}