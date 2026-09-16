rule TTP_XOR_WriteProcessMemory_aa0a {
  strings:
    $key_aa0a = { fd 78 [2] cf 5a [2] c9 6f [2] e7 6f [2] d8 73 }

  condition:
    any of them
}