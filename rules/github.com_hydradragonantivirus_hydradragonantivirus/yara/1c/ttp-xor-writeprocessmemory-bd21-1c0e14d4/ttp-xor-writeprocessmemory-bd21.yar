rule TTP_XOR_WriteProcessMemory_bd21 {
  strings:
    $key_bd21 = { ea 53 [2] d8 71 [2] de 44 [2] f0 44 [2] cf 58 }

  condition:
    any of them
}