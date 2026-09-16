rule TTP_XOR_WriteProcessMemory_aa10 {
  strings:
    $key_aa10 = { fd 62 [2] cf 40 [2] c9 75 [2] e7 75 [2] d8 69 }

  condition:
    any of them
}