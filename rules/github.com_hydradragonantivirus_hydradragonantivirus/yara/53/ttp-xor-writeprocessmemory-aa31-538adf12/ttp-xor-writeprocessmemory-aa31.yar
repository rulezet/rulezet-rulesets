rule TTP_XOR_WriteProcessMemory_aa31 {
  strings:
    $key_aa31 = { fd 43 [2] cf 61 [2] c9 54 [2] e7 54 [2] d8 48 }

  condition:
    any of them
}