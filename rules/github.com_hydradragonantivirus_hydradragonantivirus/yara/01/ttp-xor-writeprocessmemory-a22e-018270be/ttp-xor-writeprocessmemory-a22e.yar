rule TTP_XOR_WriteProcessMemory_a22e {
  strings:
    $key_a22e = { f5 5c [2] c7 7e [2] c1 4b [2] ef 4b [2] d0 57 }

  condition:
    any of them
}