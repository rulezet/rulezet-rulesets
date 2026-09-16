rule TTP_XOR_WriteProcessMemory_a74d {
  strings:
    $key_a74d = { f0 3f [2] c2 1d [2] c4 28 [2] ea 28 [2] d5 34 }

  condition:
    any of them
}