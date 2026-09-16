rule TTP_XOR_WriteProcessMemory_aa6b {
  strings:
    $key_aa6b = { fd 19 [2] cf 3b [2] c9 0e [2] e7 0e [2] d8 12 }

  condition:
    any of them
}