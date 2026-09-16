rule TTP_XOR_WriteProcessMemory_bdf2 {
  strings:
    $key_bdf2 = { ea 80 [2] d8 a2 [2] de 97 [2] f0 97 [2] cf 8b }

  condition:
    any of them
}