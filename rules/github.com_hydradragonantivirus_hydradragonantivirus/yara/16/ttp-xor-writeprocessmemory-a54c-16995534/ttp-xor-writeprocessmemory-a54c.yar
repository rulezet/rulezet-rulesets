rule TTP_XOR_WriteProcessMemory_a54c {
  strings:
    $key_a54c = { f2 3e [2] c0 1c [2] c6 29 [2] e8 29 [2] d7 35 }

  condition:
    any of them
}