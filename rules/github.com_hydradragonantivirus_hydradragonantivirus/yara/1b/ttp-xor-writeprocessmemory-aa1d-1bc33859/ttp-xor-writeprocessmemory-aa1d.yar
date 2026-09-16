rule TTP_XOR_WriteProcessMemory_aa1d {
  strings:
    $key_aa1d = { fd 6f [2] cf 4d [2] c9 78 [2] e7 78 [2] d8 64 }

  condition:
    any of them
}