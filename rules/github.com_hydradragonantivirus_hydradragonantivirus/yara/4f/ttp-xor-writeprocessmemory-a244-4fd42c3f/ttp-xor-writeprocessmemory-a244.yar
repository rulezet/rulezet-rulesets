rule TTP_XOR_WriteProcessMemory_a244 {
  strings:
    $key_a244 = { f5 36 [2] c7 14 [2] c1 21 [2] ef 21 [2] d0 3d }

  condition:
    any of them
}