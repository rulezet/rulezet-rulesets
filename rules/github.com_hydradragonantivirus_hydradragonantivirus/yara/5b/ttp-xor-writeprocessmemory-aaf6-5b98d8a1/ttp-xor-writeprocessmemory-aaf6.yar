rule TTP_XOR_WriteProcessMemory_aaf6 {
  strings:
    $key_aaf6 = { fd 84 [2] cf a6 [2] c9 93 [2] e7 93 [2] d8 8f }

  condition:
    any of them
}