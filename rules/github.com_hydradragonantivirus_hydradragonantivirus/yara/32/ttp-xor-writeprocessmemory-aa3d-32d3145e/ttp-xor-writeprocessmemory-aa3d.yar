rule TTP_XOR_WriteProcessMemory_aa3d {
  strings:
    $key_aa3d = { fd 4f [2] cf 6d [2] c9 58 [2] e7 58 [2] d8 44 }

  condition:
    any of them
}