rule TTP_XOR_WriteProcessMemory_6e4f {
  strings:
    $key_6e4f = { 39 3d [2] 0b 1f [2] 0d 2a [2] 23 2a [2] 1c 36 }

  condition:
    any of them
}