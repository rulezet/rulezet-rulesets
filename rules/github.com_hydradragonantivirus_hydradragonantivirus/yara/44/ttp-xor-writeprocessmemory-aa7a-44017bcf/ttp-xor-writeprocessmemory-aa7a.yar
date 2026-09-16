rule TTP_XOR_WriteProcessMemory_aa7a {
  strings:
    $key_aa7a = { fd 08 [2] cf 2a [2] c9 1f [2] e7 1f [2] d8 03 }

  condition:
    any of them
}