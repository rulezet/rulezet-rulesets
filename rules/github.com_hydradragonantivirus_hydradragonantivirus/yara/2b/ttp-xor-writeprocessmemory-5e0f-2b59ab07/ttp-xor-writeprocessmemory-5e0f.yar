rule TTP_XOR_WriteProcessMemory_5e0f {
  strings:
    $key_5e0f = { 09 7d [2] 3b 5f [2] 3d 6a [2] 13 6a [2] 2c 76 }

  condition:
    any of them
}