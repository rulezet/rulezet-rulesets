rule TTP_XOR_WriteProcessMemory_bdf1 {
  strings:
    $key_bdf1 = { ea 83 [2] d8 a1 [2] de 94 [2] f0 94 [2] cf 88 }

  condition:
    any of them
}