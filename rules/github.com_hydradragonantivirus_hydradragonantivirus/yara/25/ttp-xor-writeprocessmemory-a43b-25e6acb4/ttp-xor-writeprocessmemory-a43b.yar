rule TTP_XOR_WriteProcessMemory_a43b {
  strings:
    $key_a43b = { f3 49 [2] c1 6b [2] c7 5e [2] e9 5e [2] d6 42 }

  condition:
    any of them
}