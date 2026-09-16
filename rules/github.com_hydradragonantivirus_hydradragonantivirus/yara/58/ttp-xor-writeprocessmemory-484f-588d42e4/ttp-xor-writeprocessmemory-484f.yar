rule TTP_XOR_WriteProcessMemory_484f {
  strings:
    $key_484f = { 1f 3d [2] 2d 1f [2] 2b 2a [2] 05 2a [2] 3a 36 }

  condition:
    any of them
}