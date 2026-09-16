rule TTP_XOR_WriteProcessMemory_a3d1 {
  strings:
    $key_a3d1 = { f4 a3 [2] c6 81 [2] c0 b4 [2] ee b4 [2] d1 a8 }

  condition:
    any of them
}