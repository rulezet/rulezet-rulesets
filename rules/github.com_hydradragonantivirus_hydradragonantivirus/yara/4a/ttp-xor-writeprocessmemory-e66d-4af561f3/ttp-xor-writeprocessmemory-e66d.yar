rule TTP_XOR_WriteProcessMemory_e66d {
  strings:
    $key_e66d = { b1 1f [2] 83 3d [2] 85 08 [2] ab 08 [2] 94 14 }

  condition:
    any of them
}