rule TTP_XOR_WriteProcessMemory_a758 {
  strings:
    $key_a758 = { f0 2a [2] c2 08 [2] c4 3d [2] ea 3d [2] d5 21 }

  condition:
    any of them
}