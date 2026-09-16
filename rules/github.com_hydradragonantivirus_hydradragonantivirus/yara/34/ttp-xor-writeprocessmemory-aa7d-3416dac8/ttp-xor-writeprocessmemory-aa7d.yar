rule TTP_XOR_WriteProcessMemory_aa7d {
  strings:
    $key_aa7d = { fd 0f [2] cf 2d [2] c9 18 [2] e7 18 [2] d8 04 }

  condition:
    any of them
}