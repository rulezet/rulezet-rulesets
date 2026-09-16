rule TTP_XOR_WriteProcessMemory_7e4f {
  strings:
    $key_7e4f = { 29 3d [2] 1b 1f [2] 1d 2a [2] 33 2a [2] 0c 36 }

  condition:
    any of them
}