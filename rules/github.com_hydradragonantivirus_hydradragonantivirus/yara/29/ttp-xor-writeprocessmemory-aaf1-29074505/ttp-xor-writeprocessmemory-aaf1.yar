rule TTP_XOR_WriteProcessMemory_aaf1 {
  strings:
    $key_aaf1 = { fd 83 [2] cf a1 [2] c9 94 [2] e7 94 [2] d8 88 }

  condition:
    any of them
}