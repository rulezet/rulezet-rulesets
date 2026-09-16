rule TTP_XOR_WriteProcessMemory_a21c {
  strings:
    $key_a21c = { f5 6e [2] c7 4c [2] c1 79 [2] ef 79 [2] d0 65 }

  condition:
    any of them
}