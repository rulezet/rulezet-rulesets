rule TTP_XOR_WriteProcessMemory_aaf9 {
  strings:
    $key_aaf9 = { fd 8b [2] cf a9 [2] c9 9c [2] e7 9c [2] d8 80 }

  condition:
    any of them
}