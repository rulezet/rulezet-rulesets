rule TTP_XOR_WriteProcessMemory_aa48 {
  strings:
    $key_aa48 = { fd 3a [2] cf 18 [2] c9 2d [2] e7 2d [2] d8 31 }

  condition:
    any of them
}