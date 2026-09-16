rule TTP_XOR_WriteProcessMemory_b44f {
  strings:
    $key_b44f = { e3 3d [2] d1 1f [2] d7 2a [2] f9 2a [2] c6 36 }

  condition:
    any of them
}