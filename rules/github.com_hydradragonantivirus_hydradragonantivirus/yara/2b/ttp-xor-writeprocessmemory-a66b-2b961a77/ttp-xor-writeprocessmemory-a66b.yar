rule TTP_XOR_WriteProcessMemory_a66b {
  strings:
    $key_a66b = { f1 19 [2] c3 3b [2] c5 0e [2] eb 0e [2] d4 12 }

  condition:
    any of them
}