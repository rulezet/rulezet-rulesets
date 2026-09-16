rule TTP_XOR_WriteProcessMemory_aa6f {
  strings:
    $key_aa6f = { fd 1d [2] cf 3f [2] c9 0a [2] e7 0a [2] d8 16 }

  condition:
    any of them
}