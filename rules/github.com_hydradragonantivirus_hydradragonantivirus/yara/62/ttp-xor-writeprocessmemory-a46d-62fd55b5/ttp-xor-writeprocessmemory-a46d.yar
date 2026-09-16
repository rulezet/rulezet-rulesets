rule TTP_XOR_WriteProcessMemory_a46d {
  strings:
    $key_a46d = { f3 1f [2] c1 3d [2] c7 08 [2] e9 08 [2] d6 14 }

  condition:
    any of them
}