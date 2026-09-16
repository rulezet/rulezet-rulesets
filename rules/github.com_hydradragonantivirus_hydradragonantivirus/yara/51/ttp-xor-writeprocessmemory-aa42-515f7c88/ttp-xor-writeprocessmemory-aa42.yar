rule TTP_XOR_WriteProcessMemory_aa42 {
  strings:
    $key_aa42 = { fd 30 [2] cf 12 [2] c9 27 [2] e7 27 [2] d8 3b }

  condition:
    any of them
}