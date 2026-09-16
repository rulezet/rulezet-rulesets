rule TTP_XOR_WriteProcessMemory_544f {
  strings:
    $key_544f = { 03 3d [2] 31 1f [2] 37 2a [2] 19 2a [2] 26 36 }

  condition:
    any of them
}