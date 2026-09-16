rule TTP_XOR_WriteProcessMemory_654f {
  strings:
    $key_654f = { 32 3d [2] 00 1f [2] 06 2a [2] 28 2a [2] 17 36 }

  condition:
    any of them
}