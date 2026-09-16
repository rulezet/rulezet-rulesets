rule TTP_XOR_WriteProcessMemory_aa1b {
  strings:
    $key_aa1b = { fd 69 [2] cf 4b [2] c9 7e [2] e7 7e [2] d8 62 }

  condition:
    any of them
}