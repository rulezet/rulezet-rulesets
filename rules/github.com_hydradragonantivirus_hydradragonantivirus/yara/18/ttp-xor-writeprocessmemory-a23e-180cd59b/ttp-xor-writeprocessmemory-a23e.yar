rule TTP_XOR_WriteProcessMemory_a23e {
  strings:
    $key_a23e = { f5 4c [2] c7 6e [2] c1 5b [2] ef 5b [2] d0 47 }

  condition:
    any of them
}