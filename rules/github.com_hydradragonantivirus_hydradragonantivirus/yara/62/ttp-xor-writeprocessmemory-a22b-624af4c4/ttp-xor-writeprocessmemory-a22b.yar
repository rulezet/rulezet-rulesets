rule TTP_XOR_WriteProcessMemory_a22b {
  strings:
    $key_a22b = { f5 59 [2] c7 7b [2] c1 4e [2] ef 4e [2] d0 52 }

  condition:
    any of them
}