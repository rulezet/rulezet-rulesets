rule TTP_XOR_WriteProcessMemory_aa63 {
  strings:
    $key_aa63 = { fd 11 [2] cf 33 [2] c9 06 [2] e7 06 [2] d8 1a }

  condition:
    any of them
}