rule TTP_XOR_WriteProcessMemory_b16d {
  strings:
    $key_b16d = { e6 1f [2] d4 3d [2] d2 08 [2] fc 08 [2] c3 14 }

  condition:
    any of them
}