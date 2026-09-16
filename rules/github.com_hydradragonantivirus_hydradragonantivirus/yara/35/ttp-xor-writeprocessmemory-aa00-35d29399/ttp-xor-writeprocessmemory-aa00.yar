rule TTP_XOR_WriteProcessMemory_aa00 {
  strings:
    $key_aa00 = { fd 72 [2] cf 50 [2] c9 65 [2] e7 65 [2] d8 79 }

  condition:
    any of them
}