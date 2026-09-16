rule TTP_XOR_WriteProcessMemory_505f {
  strings:
    $key_505f = { 07 2d [2] 35 0f [2] 33 3a [2] 1d 3a [2] 22 26 }

  condition:
    any of them
}