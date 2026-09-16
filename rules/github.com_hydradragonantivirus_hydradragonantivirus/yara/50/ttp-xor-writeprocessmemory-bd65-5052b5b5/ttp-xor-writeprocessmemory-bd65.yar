rule TTP_XOR_WriteProcessMemory_bd65 {
  strings:
    $key_bd65 = { ea 17 [2] d8 35 [2] de 00 [2] f0 00 [2] cf 1c }

  condition:
    any of them
}