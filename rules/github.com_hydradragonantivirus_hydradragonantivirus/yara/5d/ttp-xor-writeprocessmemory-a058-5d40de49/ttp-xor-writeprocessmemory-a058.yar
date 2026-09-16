rule TTP_XOR_WriteProcessMemory_a058 {
  strings:
    $key_a058 = { f7 2a [2] c5 08 [2] c3 3d [2] ed 3d [2] d2 21 }

  condition:
    any of them
}