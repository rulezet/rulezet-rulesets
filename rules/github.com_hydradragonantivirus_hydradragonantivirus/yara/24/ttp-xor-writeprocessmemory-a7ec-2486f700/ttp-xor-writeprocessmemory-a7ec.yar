rule TTP_XOR_WriteProcessMemory_a7ec {
  strings:
    $key_a7ec = { f0 9e [2] c2 bc [2] c4 89 [2] ea 89 [2] d5 95 }

  condition:
    any of them
}