rule TTP_XOR_WriteProcessMemory_aaf7 {
  strings:
    $key_aaf7 = { fd 85 [2] cf a7 [2] c9 92 [2] e7 92 [2] d8 8e }

  condition:
    any of them
}