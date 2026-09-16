rule TTP_XOR_WriteProcessMemory_aa7b {
  strings:
    $key_aa7b = { fd 09 [2] cf 2b [2] c9 1e [2] e7 1e [2] d8 02 }

  condition:
    any of them
}