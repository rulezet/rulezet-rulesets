rule TTP_XOR_WriteProcessMemory_aa0e {
  strings:
    $key_aa0e = { fd 7c [2] cf 5e [2] c9 6b [2] e7 6b [2] d8 77 }

  condition:
    any of them
}