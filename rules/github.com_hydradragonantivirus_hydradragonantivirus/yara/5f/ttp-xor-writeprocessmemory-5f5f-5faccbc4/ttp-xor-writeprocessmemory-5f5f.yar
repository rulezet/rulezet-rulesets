rule TTP_XOR_WriteProcessMemory_5f5f {
  strings:
    $key_5f5f = { 08 2d [2] 3a 0f [2] 3c 3a [2] 12 3a [2] 2d 26 }

  condition:
    any of them
}