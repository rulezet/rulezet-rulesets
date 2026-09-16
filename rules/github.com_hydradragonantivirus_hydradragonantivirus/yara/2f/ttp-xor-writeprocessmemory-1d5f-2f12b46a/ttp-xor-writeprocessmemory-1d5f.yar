rule TTP_XOR_WriteProcessMemory_1d5f {
  strings:
    $key_1d5f = { 4a 2d [2] 78 0f [2] 7e 3a [2] 50 3a [2] 6f 26 }

  condition:
    any of them
}