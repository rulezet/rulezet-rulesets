rule TTP_XOR_WriteProcessMemory_bdf6 {
  strings:
    $key_bdf6 = { ea 84 [2] d8 a6 [2] de 93 [2] f0 93 [2] cf 8f }

  condition:
    any of them
}