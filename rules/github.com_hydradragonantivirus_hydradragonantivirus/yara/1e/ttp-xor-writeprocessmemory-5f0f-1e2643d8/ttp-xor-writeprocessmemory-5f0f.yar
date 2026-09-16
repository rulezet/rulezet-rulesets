rule TTP_XOR_WriteProcessMemory_5f0f {
  strings:
    $key_5f0f = { 08 7d [2] 3a 5f [2] 3c 6a [2] 12 6a [2] 2d 76 }

  condition:
    any of them
}