rule TTP_XOR_WriteProcessMemory_814f {
  strings:
    $key_814f = { d6 3d [2] e4 1f [2] e2 2a [2] cc 2a [2] f3 36 }

  condition:
    any of them
}