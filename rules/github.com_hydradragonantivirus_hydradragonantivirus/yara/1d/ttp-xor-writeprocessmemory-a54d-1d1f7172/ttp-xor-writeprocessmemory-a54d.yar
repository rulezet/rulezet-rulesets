rule TTP_XOR_WriteProcessMemory_a54d {
  strings:
    $key_a54d = { f2 3f [2] c0 1d [2] c6 28 [2] e8 28 [2] d7 34 }

  condition:
    any of them
}