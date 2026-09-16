rule TTP_XOR_WriteProcessMemory_a3d5 {
  strings:
    $key_a3d5 = { f4 a7 [2] c6 85 [2] c0 b0 [2] ee b0 [2] d1 ac }

  condition:
    any of them
}