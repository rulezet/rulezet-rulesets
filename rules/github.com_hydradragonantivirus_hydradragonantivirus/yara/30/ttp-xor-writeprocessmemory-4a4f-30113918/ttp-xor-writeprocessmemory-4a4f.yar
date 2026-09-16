rule TTP_XOR_WriteProcessMemory_4a4f {
  strings:
    $key_4a4f = { 1d 3d [2] 2f 1f [2] 29 2a [2] 07 2a [2] 38 36 }

  condition:
    any of them
}