rule TTP_XOR_WriteProcessMemory_bd66 {
  strings:
    $key_bd66 = { ea 14 [2] d8 36 [2] de 03 [2] f0 03 [2] cf 1f }

  condition:
    any of them
}