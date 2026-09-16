rule TTP_XOR_WriteProcessMemory_3d5f {
  strings:
    $key_3d5f = { 6a 2d [2] 58 0f [2] 5e 3a [2] 70 3a [2] 4f 26 }

  condition:
    any of them
}