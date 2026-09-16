rule TTP_XOR_WriteProcessMemory_b30e {
  strings:
    $key_b30e = { e4 7c [2] d6 5e [2] d0 6b [2] fe 6b [2] c1 77 }

  condition:
    any of them
}