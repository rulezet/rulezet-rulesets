rule TTP_XOR_WriteProcessMemory_a658 {
  strings:
    $key_a658 = { f1 2a [2] c3 08 [2] c5 3d [2] eb 3d [2] d4 21 }

  condition:
    any of them
}