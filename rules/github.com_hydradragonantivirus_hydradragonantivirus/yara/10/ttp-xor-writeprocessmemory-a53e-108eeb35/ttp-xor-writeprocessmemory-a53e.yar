rule TTP_XOR_WriteProcessMemory_a53e {
  strings:
    $key_a53e = { f2 4c [2] c0 6e [2] c6 5b [2] e8 5b [2] d7 47 }

  condition:
    any of them
}