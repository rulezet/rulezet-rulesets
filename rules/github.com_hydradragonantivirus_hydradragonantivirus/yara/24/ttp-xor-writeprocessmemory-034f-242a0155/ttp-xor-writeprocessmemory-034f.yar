rule TTP_XOR_WriteProcessMemory_034f {
  strings:
    $key_034f = { 54 3d [2] 66 1f [2] 60 2a [2] 4e 2a [2] 71 36 }

  condition:
    any of them
}