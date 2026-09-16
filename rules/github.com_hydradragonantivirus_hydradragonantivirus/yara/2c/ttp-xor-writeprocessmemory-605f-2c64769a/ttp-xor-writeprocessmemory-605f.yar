rule TTP_XOR_WriteProcessMemory_605f {
  strings:
    $key_605f = { 37 2d [2] 05 0f [2] 03 3a [2] 2d 3a [2] 12 26 }

  condition:
    any of them
}