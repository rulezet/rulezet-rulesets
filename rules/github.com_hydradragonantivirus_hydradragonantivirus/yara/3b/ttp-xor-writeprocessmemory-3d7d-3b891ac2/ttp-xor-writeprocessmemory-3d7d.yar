rule TTP_XOR_WriteProcessMemory_3d7d {
  strings:
    $key_3d7d = { 6a 0f [2] 58 2d [2] 5e 18 [2] 70 18 [2] 4f 04 }

  condition:
    any of them
}