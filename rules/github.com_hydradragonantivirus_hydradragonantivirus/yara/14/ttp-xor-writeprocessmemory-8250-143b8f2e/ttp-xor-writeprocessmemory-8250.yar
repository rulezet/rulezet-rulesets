rule TTP_XOR_WriteProcessMemory_8250 {
  strings:
    $key_8250 = { d5 22 [2] e7 00 [2] e1 35 [2] cf 35 [2] f0 29 }

  condition:
    any of them
}