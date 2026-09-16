rule TTP_XOR_WriteProcessMemory_714f {
  strings:
    $key_714f = { 26 3d [2] 14 1f [2] 12 2a [2] 3c 2a [2] 03 36 }

  condition:
    any of them
}