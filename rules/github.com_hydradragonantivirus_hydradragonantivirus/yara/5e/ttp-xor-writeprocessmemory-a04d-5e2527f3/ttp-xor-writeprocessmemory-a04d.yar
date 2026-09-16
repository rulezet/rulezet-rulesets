rule TTP_XOR_WriteProcessMemory_a04d {
  strings:
    $key_a04d = { f7 3f [2] c5 1d [2] c3 28 [2] ed 28 [2] d2 34 }

  condition:
    any of them
}