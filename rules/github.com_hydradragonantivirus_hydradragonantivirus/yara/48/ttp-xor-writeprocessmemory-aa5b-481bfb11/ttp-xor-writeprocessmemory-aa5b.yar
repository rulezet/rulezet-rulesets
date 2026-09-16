rule TTP_XOR_WriteProcessMemory_aa5b {
  strings:
    $key_aa5b = { fd 29 [2] cf 0b [2] c9 3e [2] e7 3e [2] d8 22 }

  condition:
    any of them
}