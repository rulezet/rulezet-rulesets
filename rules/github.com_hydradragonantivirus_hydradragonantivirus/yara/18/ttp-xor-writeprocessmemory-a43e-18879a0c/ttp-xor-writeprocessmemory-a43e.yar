rule TTP_XOR_WriteProcessMemory_a43e {
  strings:
    $key_a43e = { f3 4c [2] c1 6e [2] c7 5b [2] e9 5b [2] d6 47 }

  condition:
    any of them
}