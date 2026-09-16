rule TTP_XOR_WriteProcessMemory_a76d {
  strings:
    $key_a76d = { f0 1f [2] c2 3d [2] c4 08 [2] ea 08 [2] d5 14 }

  condition:
    any of them
}