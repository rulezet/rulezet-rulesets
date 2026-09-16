rule TTP_XOR_WriteProcessMemory_585f {
  strings:
    $key_585f = { 0f 2d [2] 3d 0f [2] 3b 3a [2] 15 3a [2] 2a 26 }

  condition:
    any of them
}