rule TTP_XOR_WriteProcessMemory_a25c {
  strings:
    $key_a25c = { f5 2e [2] c7 0c [2] c1 39 [2] ef 39 [2] d0 25 }

  condition:
    any of them
}