rule TTP_XOR_WriteProcessMemory_b33e {
  strings:
    $key_b33e = { e4 4c [2] d6 6e [2] d0 5b [2] fe 5b [2] c1 47 }

  condition:
    any of them
}