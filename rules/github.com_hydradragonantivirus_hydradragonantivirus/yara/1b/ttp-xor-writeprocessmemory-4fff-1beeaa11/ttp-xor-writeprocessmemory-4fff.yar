rule TTP_XOR_WriteProcessMemory_4fff {
  strings:
    $key_4fff = { 18 8d [2] 2a af [2] 2c 9a [2] 02 9a [2] 3d 86 }

  condition:
    any of them
}