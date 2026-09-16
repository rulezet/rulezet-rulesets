rule TTP_XOR_WriteProcessMemory_655f {
  strings:
    $key_655f = { 32 2d [2] 00 0f [2] 06 3a [2] 28 3a [2] 17 26 }

  condition:
    any of them
}