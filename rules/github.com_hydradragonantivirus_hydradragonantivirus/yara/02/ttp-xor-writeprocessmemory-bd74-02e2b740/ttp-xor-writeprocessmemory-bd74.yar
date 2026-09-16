rule TTP_XOR_WriteProcessMemory_bd74 {
  strings:
    $key_bd74 = { ea 06 [2] d8 24 [2] de 11 [2] f0 11 [2] cf 0d }

  condition:
    any of them
}