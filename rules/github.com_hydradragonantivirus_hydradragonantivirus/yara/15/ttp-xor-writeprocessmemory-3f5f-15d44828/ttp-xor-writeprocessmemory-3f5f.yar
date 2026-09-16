rule TTP_XOR_WriteProcessMemory_3f5f {
  strings:
    $key_3f5f = { 68 2d [2] 5a 0f [2] 5c 3a [2] 72 3a [2] 4d 26 }

  condition:
    any of them
}