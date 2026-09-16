rule TTP_XOR_WriteProcessMemory_974f {
  strings:
    $key_974f = { c0 3d [2] f2 1f [2] f4 2a [2] da 2a [2] e5 36 }

  condition:
    any of them
}