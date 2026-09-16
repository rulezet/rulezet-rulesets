rule TTP_XOR_WriteProcessMemory_8256 {
  strings:
    $key_8256 = { d5 24 [2] e7 06 [2] e1 33 [2] cf 33 [2] f0 2f }

  condition:
    any of them
}