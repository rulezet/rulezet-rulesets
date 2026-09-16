rule TTP_XOR_WriteProcessMemory_aaf3 {
  strings:
    $key_aaf3 = { fd 81 [2] cf a3 [2] c9 96 [2] e7 96 [2] d8 8a }

  condition:
    any of them
}