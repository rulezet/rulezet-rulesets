rule TTP_XOR_WriteProcessMemory_a26c {
  strings:
    $key_a26c = { f5 1e [2] c7 3c [2] c1 09 [2] ef 09 [2] d0 15 }

  condition:
    any of them
}