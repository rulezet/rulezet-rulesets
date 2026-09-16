rule TTP_XOR_WriteProcessMemory_aa26 {
  strings:
    $key_aa26 = { fd 54 [2] cf 76 [2] c9 43 [2] e7 43 [2] d8 5f }

  condition:
    any of them
}