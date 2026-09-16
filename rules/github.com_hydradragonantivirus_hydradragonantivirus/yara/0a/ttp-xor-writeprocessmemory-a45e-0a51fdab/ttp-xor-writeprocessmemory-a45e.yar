rule TTP_XOR_WriteProcessMemory_a45e {
  strings:
    $key_a45e = { f3 2c [2] c1 0e [2] c7 3b [2] e9 3b [2] d6 27 }

  condition:
    any of them
}