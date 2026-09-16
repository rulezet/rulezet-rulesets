rule TTP_XOR_WriteProcessMemory_5e4f {
  strings:
    $key_5e4f = { 09 3d [2] 3b 1f [2] 3d 2a [2] 13 2a [2] 2c 36 }

  condition:
    any of them
}