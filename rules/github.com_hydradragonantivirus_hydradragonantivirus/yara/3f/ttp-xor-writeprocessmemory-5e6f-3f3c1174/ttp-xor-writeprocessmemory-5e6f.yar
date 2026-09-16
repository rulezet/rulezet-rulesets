rule TTP_XOR_WriteProcessMemory_5e6f {
  strings:
    $key_5e6f = { 09 1d [2] 3b 3f [2] 3d 0a [2] 13 0a [2] 2c 16 }

  condition:
    any of them
}