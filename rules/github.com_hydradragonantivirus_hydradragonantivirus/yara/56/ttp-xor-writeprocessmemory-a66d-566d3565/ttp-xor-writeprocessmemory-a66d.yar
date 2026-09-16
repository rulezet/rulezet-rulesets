rule TTP_XOR_WriteProcessMemory_a66d {
  strings:
    $key_a66d = { f1 1f [2] c3 3d [2] c5 08 [2] eb 08 [2] d4 14 }

  condition:
    any of them
}