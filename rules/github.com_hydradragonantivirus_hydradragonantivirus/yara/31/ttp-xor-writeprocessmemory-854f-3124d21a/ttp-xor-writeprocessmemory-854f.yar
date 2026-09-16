rule TTP_XOR_WriteProcessMemory_854f {
  strings:
    $key_854f = { d2 3d [2] e0 1f [2] e6 2a [2] c8 2a [2] f7 36 }

  condition:
    any of them
}