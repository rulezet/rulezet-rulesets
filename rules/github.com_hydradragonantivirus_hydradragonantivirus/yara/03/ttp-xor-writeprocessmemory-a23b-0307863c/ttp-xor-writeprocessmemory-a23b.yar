rule TTP_XOR_WriteProcessMemory_a23b {
  strings:
    $key_a23b = { f5 49 [2] c7 6b [2] c1 5e [2] ef 5e [2] d0 42 }

  condition:
    any of them
}