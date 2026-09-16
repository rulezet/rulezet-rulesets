rule TTP_XOR_WriteProcessMemory_b36d {
  strings:
    $key_b36d = { e4 1f [2] d6 3d [2] d0 08 [2] fe 08 [2] c1 14 }

  condition:
    any of them
}