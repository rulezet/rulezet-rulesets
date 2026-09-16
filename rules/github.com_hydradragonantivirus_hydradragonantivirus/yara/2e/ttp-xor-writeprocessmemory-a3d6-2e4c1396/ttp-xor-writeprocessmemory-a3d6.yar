rule TTP_XOR_WriteProcessMemory_a3d6 {
  strings:
    $key_a3d6 = { f4 a4 [2] c6 86 [2] c0 b3 [2] ee b3 [2] d1 af }

  condition:
    any of them
}