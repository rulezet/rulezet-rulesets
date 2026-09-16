rule TTP_XOR_WriteProcessMemory_bd04 {
  strings:
    $key_bd04 = { ea 76 [2] d8 54 [2] de 61 [2] f0 61 [2] cf 7d }

  condition:
    any of them
}