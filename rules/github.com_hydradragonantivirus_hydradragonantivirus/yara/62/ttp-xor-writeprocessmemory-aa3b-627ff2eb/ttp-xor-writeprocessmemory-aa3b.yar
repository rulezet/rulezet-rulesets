rule TTP_XOR_WriteProcessMemory_aa3b {
  strings:
    $key_aa3b = { fd 49 [2] cf 6b [2] c9 5e [2] e7 5e [2] d8 42 }

  condition:
    any of them
}