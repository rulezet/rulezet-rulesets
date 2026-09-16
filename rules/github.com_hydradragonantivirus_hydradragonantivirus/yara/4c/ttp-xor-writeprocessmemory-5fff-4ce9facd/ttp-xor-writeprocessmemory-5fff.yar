rule TTP_XOR_WriteProcessMemory_5fff {
  strings:
    $key_5fff = { 08 8d [2] 3a af [2] 3c 9a [2] 12 9a [2] 2d 86 }

  condition:
    any of them
}