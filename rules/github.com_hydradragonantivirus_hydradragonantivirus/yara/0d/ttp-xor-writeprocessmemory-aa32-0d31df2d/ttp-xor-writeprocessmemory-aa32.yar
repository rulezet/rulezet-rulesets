rule TTP_XOR_WriteProcessMemory_aa32 {
  strings:
    $key_aa32 = { fd 40 [2] cf 62 [2] c9 57 [2] e7 57 [2] d8 4b }

  condition:
    any of them
}