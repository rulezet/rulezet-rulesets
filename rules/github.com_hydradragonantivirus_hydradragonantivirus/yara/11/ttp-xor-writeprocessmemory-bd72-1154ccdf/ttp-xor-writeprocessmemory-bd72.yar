rule TTP_XOR_WriteProcessMemory_bd72 {
  strings:
    $key_bd72 = { ea 00 [2] d8 22 [2] de 17 [2] f0 17 [2] cf 0b }

  condition:
    any of them
}