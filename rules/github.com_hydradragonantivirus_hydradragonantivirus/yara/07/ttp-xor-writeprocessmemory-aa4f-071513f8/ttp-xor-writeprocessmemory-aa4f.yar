rule TTP_XOR_WriteProcessMemory_aa4f {
  strings:
    $key_aa4f = { fd 3d [2] cf 1f [2] c9 2a [2] e7 2a [2] d8 36 }

  condition:
    any of them
}