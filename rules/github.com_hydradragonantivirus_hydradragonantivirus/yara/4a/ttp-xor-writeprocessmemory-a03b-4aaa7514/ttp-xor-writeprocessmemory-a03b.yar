rule TTP_XOR_WriteProcessMemory_a03b {
  strings:
    $key_a03b = { f7 49 [2] c5 6b [2] c3 5e [2] ed 5e [2] d2 42 }

  condition:
    any of them
}