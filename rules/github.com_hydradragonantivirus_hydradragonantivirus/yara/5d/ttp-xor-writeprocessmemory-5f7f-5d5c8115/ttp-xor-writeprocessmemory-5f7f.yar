rule TTP_XOR_WriteProcessMemory_5f7f {
  strings:
    $key_5f7f = { 08 0d [2] 3a 2f [2] 3c 1a [2] 12 1a [2] 2d 06 }

  condition:
    any of them
}