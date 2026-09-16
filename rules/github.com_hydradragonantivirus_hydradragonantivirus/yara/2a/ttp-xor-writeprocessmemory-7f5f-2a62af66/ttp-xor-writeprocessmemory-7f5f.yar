rule TTP_XOR_WriteProcessMemory_7f5f {
  strings:
    $key_7f5f = { 28 2d [2] 1a 0f [2] 1c 3a [2] 32 3a [2] 0d 26 }

  condition:
    any of them
}