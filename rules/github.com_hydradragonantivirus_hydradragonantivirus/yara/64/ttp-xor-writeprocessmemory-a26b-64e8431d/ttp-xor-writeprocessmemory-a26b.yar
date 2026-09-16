rule TTP_XOR_WriteProcessMemory_a26b {
  strings:
    $key_a26b = { f5 19 [2] c7 3b [2] c1 0e [2] ef 0e [2] d0 12 }

  condition:
    any of them
}