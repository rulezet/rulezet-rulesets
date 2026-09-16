rule TTP_XOR_WriteProcessMemory_aa55 {
  strings:
    $key_aa55 = { fd 27 [2] cf 05 [2] c9 30 [2] e7 30 [2] d8 2c }

  condition:
    any of them
}