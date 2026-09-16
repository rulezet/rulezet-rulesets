rule TTP_XOR_WriteProcessMemory_bd53 {
  strings:
    $key_bd53 = { ea 21 [2] d8 03 [2] de 36 [2] f0 36 [2] cf 2a }

  condition:
    any of them
}