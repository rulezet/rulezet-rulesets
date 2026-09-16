rule TTP_XOR_WriteProcessMemory_bd43 {
  strings:
    $key_bd43 = { ea 31 [2] d8 13 [2] de 26 [2] f0 26 [2] cf 3a }

  condition:
    any of them
}