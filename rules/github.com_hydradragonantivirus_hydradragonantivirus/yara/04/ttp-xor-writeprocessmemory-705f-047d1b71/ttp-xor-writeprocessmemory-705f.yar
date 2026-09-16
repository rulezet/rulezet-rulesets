rule TTP_XOR_WriteProcessMemory_705f {
  strings:
    $key_705f = { 27 2d [2] 15 0f [2] 13 3a [2] 3d 3a [2] 02 26 }

  condition:
    any of them
}