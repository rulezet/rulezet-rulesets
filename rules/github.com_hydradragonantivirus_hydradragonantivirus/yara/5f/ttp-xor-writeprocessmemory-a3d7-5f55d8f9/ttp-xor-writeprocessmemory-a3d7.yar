rule TTP_XOR_WriteProcessMemory_a3d7 {
  strings:
    $key_a3d7 = { f4 a5 [2] c6 87 [2] c0 b2 [2] ee b2 [2] d1 ae }

  condition:
    any of them
}