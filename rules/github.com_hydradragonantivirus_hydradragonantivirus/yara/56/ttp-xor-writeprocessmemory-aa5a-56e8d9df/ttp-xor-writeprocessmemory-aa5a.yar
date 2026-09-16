rule TTP_XOR_WriteProcessMemory_aa5a {
  strings:
    $key_aa5a = { fd 28 [2] cf 0a [2] c9 3f [2] e7 3f [2] d8 23 }

  condition:
    any of them
}