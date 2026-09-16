rule TTP_XOR_WriteProcessMemory_b3ec {
  strings:
    $key_b3ec = { e4 9e [2] d6 bc [2] d0 89 [2] fe 89 [2] c1 95 }

  condition:
    any of them
}