rule TTP_XOR_WriteProcessMemory_a44d {
  strings:
    $key_a44d = { f3 3f [2] c1 1d [2] c7 28 [2] e9 28 [2] d6 34 }

  condition:
    any of them
}