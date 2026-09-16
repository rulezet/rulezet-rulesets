rule TTP_XOR_WriteProcessMemory_a56b {
  strings:
    $key_a56b = { f2 19 [2] c0 3b [2] c6 0e [2] e8 0e [2] d7 12 }

  condition:
    any of them
}