rule TTP_XOR_WriteProcessMemory_bd02 {
  strings:
    $key_bd02 = { ea 70 [2] d8 52 [2] de 67 [2] f0 67 [2] cf 7b }

  condition:
    any of them
}