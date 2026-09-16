rule TTP_XOR_WriteProcessMemory_aaca {
  strings:
    $key_aaca = { fd b8 [2] cf 9a [2] c9 af [2] e7 af [2] d8 b3 }

  condition:
    any of them
}