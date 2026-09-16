rule TTP_XOR_WriteProcessMemory_aa74 {
  strings:
    $key_aa74 = { fd 06 [2] cf 24 [2] c9 11 [2] e7 11 [2] d8 0d }

  condition:
    any of them
}