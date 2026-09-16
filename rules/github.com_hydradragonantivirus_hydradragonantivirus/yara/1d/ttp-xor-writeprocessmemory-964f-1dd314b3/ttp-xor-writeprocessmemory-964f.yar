rule TTP_XOR_WriteProcessMemory_964f {
  strings:
    $key_964f = { c1 3d [2] f3 1f [2] f5 2a [2] db 2a [2] e4 36 }

  condition:
    any of them
}