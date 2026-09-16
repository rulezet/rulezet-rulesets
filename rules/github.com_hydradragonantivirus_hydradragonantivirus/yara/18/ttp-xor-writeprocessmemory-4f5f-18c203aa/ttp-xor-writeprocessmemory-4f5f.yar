rule TTP_XOR_WriteProcessMemory_4f5f {
  strings:
    $key_4f5f = { 18 2d [2] 2a 0f [2] 2c 3a [2] 02 3a [2] 3d 26 }

  condition:
    any of them
}