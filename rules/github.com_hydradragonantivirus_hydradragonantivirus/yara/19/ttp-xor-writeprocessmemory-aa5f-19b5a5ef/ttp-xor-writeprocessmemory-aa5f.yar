rule TTP_XOR_WriteProcessMemory_aa5f {
  strings:
    $key_aa5f = { fd 2d [2] cf 0f [2] c9 3a [2] e7 3a [2] d8 26 }

  condition:
    any of them
}