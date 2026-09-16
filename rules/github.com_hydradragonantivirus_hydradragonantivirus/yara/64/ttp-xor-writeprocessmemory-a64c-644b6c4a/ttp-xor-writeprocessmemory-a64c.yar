rule TTP_XOR_WriteProcessMemory_a64c {
  strings:
    $key_a64c = { f1 3e [2] c3 1c [2] c5 29 [2] eb 29 [2] d4 35 }

  condition:
    any of them
}