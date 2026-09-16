rule TTP_XOR_WriteProcessMemory_6fff {
  strings:
    $key_6fff = { 38 8d [2] 0a af [2] 0c 9a [2] 22 9a [2] 1d 86 }

  condition:
    any of them
}