rule TTP_XOR_WriteProcessMemory_aa2e {
  strings:
    $key_aa2e = { fd 5c [2] cf 7e [2] c9 4b [2] e7 4b [2] d8 57 }

  condition:
    any of them
}