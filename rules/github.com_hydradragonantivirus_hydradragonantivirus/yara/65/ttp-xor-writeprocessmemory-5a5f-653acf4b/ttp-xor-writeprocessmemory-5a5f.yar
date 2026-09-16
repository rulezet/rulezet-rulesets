rule TTP_XOR_WriteProcessMemory_5a5f {
  strings:
    $key_5a5f = { 0d 2d [2] 3f 0f [2] 39 3a [2] 17 3a [2] 28 26 }

  condition:
    any of them
}