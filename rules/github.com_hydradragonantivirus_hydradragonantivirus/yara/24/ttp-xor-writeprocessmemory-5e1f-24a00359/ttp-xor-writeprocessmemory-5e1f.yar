rule TTP_XOR_WriteProcessMemory_5e1f {
  strings:
    $key_5e1f = { 09 6d [2] 3b 4f [2] 3d 7a [2] 13 7a [2] 2c 66 }

  condition:
    any of them
}