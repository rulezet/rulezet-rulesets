rule TTP_XOR_WriteProcessMemory_aaf5 {
  strings:
    $key_aaf5 = { fd 87 [2] cf a5 [2] c9 90 [2] e7 90 [2] d8 8c }

  condition:
    any of them
}