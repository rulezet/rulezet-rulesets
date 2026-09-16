rule TTP_XOR_WriteProcessMemory_bd32 {
  strings:
    $key_bd32 = { ea 40 [2] d8 62 [2] de 57 [2] f0 57 [2] cf 4b }

  condition:
    any of them
}