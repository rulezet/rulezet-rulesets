rule TTP_XOR_WriteProcessMemory_405f {
  strings:
    $key_405f = { 17 2d [2] 25 0f [2] 23 3a [2] 0d 3a [2] 32 26 }

  condition:
    any of them
}