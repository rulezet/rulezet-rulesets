rule TTP_XOR_WriteProcessMemory_a744 {
  strings:
    $key_a744 = { f0 36 [2] c2 14 [2] c4 21 [2] ea 21 [2] d5 3d }

  condition:
    any of them
}