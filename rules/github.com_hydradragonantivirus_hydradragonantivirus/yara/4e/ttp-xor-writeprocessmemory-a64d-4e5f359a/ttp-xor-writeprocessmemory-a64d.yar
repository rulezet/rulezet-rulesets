rule TTP_XOR_WriteProcessMemory_a64d {
  strings:
    $key_a64d = { f1 3f [2] c3 1d [2] c5 28 [2] eb 28 [2] d4 34 }

  condition:
    any of them
}