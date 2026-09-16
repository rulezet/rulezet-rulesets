rule TTP_XOR_WriteProcessMemory_aa4b {
  strings:
    $key_aa4b = { fd 39 [2] cf 1b [2] c9 2e [2] e7 2e [2] d8 32 }

  condition:
    any of them
}