rule TTP_XOR_WriteProcessMemory_aa58 {
  strings:
    $key_aa58 = { fd 2a [2] cf 08 [2] c9 3d [2] e7 3d [2] d8 21 }

  condition:
    any of them
}