rule TTP_XOR_WriteProcessMemory_406f {
  strings:
    $key_406f = { 17 1d [2] 25 3f [2] 23 0a [2] 0d 0a [2] 32 16 }

  condition:
    any of them
}