rule TTP_XOR_WriteProcessMemory_f66d {
  strings:
    $key_f66d = { a1 1f [2] 93 3d [2] 95 08 [2] bb 08 [2] 84 14 }

  condition:
    any of them
}