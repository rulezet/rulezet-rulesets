rule TTP_XOR_WriteProcessMemory_b31c {
  strings:
    $key_b31c = { e4 6e [2] d6 4c [2] d0 79 [2] fe 79 [2] c1 65 }

  condition:
    any of them
}