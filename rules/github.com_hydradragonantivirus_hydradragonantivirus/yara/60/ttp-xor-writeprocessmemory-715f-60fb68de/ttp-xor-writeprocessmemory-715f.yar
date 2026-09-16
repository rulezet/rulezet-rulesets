rule TTP_XOR_WriteProcessMemory_715f {
  strings:
    $key_715f = { 26 2d [2] 14 0f [2] 12 3a [2] 3c 3a [2] 03 26 }

  condition:
    any of them
}