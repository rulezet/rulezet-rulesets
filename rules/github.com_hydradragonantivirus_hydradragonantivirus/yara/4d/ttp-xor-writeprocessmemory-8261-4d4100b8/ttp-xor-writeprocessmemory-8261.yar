rule TTP_XOR_WriteProcessMemory_8261 {
  strings:
    $key_8261 = { d5 13 [2] e7 31 [2] e1 04 [2] cf 04 [2] f0 18 }

  condition:
    any of them
}