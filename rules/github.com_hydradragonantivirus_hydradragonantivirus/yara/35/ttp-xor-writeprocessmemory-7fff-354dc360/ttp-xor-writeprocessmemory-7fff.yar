rule TTP_XOR_WriteProcessMemory_7fff {
  strings:
    $key_7fff = { 28 8d [2] 1a af [2] 1c 9a [2] 32 9a [2] 0d 86 }

  condition:
    any of them
}