rule TTP_XOR_WriteProcessMemory_a27e {
  strings:
    $key_a27e = { f5 0c [2] c7 2e [2] c1 1b [2] ef 1b [2] d0 07 }

  condition:
    any of them
}