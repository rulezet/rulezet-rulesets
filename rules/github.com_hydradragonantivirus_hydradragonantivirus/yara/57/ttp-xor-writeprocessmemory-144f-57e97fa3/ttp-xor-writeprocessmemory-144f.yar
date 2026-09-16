rule TTP_XOR_WriteProcessMemory_144f {
  strings:
    $key_144f = { 43 3d [2] 71 1f [2] 77 2a [2] 59 2a [2] 66 36 }

  condition:
    any of them
}