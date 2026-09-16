rule TTP_XOR_WriteProcessMemory_1a5f {
  strings:
    $key_1a5f = { 4d 2d [2] 7f 0f [2] 79 3a [2] 57 3a [2] 68 26 }

  condition:
    any of them
}