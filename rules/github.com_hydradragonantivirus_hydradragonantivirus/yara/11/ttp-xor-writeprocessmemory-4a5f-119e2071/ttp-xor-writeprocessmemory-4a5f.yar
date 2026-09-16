rule TTP_XOR_WriteProcessMemory_4a5f {
  strings:
    $key_4a5f = { 1d 2d [2] 2f 0f [2] 29 3a [2] 07 3a [2] 38 26 }

  condition:
    any of them
}