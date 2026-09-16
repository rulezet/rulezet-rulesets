rule TTP_XOR_WriteProcessMemory_784f {
  strings:
    $key_784f = { 2f 3d [2] 1d 1f [2] 1b 2a [2] 35 2a [2] 0a 36 }

  condition:
    any of them
}