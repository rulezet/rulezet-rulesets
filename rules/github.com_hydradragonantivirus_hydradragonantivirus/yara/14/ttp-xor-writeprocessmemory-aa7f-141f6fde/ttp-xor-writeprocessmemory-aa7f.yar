rule TTP_XOR_WriteProcessMemory_aa7f {
  strings:
    $key_aa7f = { fd 0d [2] cf 2f [2] c9 1a [2] e7 1a [2] d8 06 }

  condition:
    any of them
}