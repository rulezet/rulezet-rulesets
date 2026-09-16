rule TTP_XOR_WriteProcessMemory_aa2b {
  strings:
    $key_aa2b = { fd 59 [2] cf 7b [2] c9 4e [2] e7 4e [2] d8 52 }

  condition:
    any of them
}