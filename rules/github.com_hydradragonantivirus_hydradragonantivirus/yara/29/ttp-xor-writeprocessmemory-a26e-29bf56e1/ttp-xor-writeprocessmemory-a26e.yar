rule TTP_XOR_WriteProcessMemory_a26e {
  strings:
    $key_a26e = { f5 1c [2] c7 3e [2] c1 0b [2] ef 0b [2] d0 17 }

  condition:
    any of them
}