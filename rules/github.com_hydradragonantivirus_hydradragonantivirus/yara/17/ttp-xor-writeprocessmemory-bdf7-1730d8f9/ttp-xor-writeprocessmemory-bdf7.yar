rule TTP_XOR_WriteProcessMemory_bdf7 {
  strings:
    $key_bdf7 = { ea 85 [2] d8 a7 [2] de 92 [2] f0 92 [2] cf 8e }

  condition:
    any of them
}