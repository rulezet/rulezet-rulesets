rule TTP_XOR_WriteProcessMemory_aa22 {
  strings:
    $key_aa22 = { fd 50 [2] cf 72 [2] c9 47 [2] e7 47 [2] d8 5b }

  condition:
    any of them
}