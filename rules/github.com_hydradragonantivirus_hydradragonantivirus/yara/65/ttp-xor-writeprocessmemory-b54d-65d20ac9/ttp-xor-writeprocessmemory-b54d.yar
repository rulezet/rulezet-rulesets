rule TTP_XOR_WriteProcessMemory_b54d {
  strings:
    $key_b54d = { e2 3f [2] d0 1d [2] d6 28 [2] f8 28 [2] c7 34 }

  condition:
    any of them
}