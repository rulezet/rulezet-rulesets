rule TTP_XOR_WriteProcessMemory_4d5f {
  strings:
    $key_4d5f = { 1a 2d [2] 28 0f [2] 2e 3a [2] 00 3a [2] 3f 26 }

  condition:
    any of them
}