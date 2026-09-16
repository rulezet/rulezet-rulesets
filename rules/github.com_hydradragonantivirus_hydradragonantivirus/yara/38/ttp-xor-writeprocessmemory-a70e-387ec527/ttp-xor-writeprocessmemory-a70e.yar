rule TTP_XOR_WriteProcessMemory_a70e {
  strings:
    $key_a70e = { f0 7c [2] c2 5e [2] c4 6b [2] ea 6b [2] d5 77 }

  condition:
    any of them
}