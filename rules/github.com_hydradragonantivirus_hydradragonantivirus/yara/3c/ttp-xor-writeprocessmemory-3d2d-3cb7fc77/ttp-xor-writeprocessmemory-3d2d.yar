rule TTP_XOR_WriteProcessMemory_3d2d {
  strings:
    $key_3d2d = { 6a 5f [2] 58 7d [2] 5e 48 [2] 70 48 [2] 4f 54 }

  condition:
    any of them
}