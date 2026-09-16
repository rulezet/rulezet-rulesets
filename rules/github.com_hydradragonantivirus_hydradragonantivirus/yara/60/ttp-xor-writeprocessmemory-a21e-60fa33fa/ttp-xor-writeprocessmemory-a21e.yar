rule TTP_XOR_WriteProcessMemory_a21e {
  strings:
    $key_a21e = { f5 6c [2] c7 4e [2] c1 7b [2] ef 7b [2] d0 67 }

  condition:
    any of them
}