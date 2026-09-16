rule TTP_XOR_WriteProcessMemory_a71c {
  strings:
    $key_a71c = { f0 6e [2] c2 4c [2] c4 79 [2] ea 79 [2] d5 65 }

  condition:
    any of them
}