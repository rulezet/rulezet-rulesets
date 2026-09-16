rule TTP_XOR_WriteProcessMemory_aa6a {
  strings:
    $key_aa6a = { fd 18 [2] cf 3a [2] c9 0f [2] e7 0f [2] d8 13 }

  condition:
    any of them
}