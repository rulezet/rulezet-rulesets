rule TTP_XOR_WriteProcessMemory_bd70 {
  strings:
    $key_bd70 = { ea 02 [2] d8 20 [2] de 15 [2] f0 15 [2] cf 09 }

  condition:
    any of them
}