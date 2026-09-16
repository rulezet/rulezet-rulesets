rule TTP_XOR_WriteProcessMemory_a56c {
  strings:
    $key_a56c = { f2 1e [2] c0 3c [2] c6 09 [2] e8 09 [2] d7 15 }

  condition:
    any of them
}