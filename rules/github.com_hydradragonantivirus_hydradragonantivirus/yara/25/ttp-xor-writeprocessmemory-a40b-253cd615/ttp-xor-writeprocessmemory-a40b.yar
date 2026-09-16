rule TTP_XOR_WriteProcessMemory_a40b {
  strings:
    $key_a40b = { f3 79 [2] c1 5b [2] c7 6e [2] e9 6e [2] d6 72 }

  condition:
    any of them
}