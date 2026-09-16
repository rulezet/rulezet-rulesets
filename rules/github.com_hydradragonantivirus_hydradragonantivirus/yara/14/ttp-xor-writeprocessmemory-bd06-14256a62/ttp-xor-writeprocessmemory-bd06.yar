rule TTP_XOR_WriteProcessMemory_bd06 {
  strings:
    $key_bd06 = { ea 74 [2] d8 56 [2] de 63 [2] f0 63 [2] cf 7f }

  condition:
    any of them
}