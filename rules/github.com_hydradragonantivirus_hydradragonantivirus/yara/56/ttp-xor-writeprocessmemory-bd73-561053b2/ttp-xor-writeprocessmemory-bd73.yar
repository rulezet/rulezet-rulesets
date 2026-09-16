rule TTP_XOR_WriteProcessMemory_bd73 {
  strings:
    $key_bd73 = { ea 01 [2] d8 23 [2] de 16 [2] f0 16 [2] cf 0a }

  condition:
    any of them
}