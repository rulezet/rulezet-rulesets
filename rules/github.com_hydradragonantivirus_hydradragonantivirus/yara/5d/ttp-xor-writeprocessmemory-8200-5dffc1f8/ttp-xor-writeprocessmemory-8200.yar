rule TTP_XOR_WriteProcessMemory_8200 {
  strings:
    $key_8200 = { d5 72 [2] e7 50 [2] e1 65 [2] cf 65 [2] f0 79 }

  condition:
    any of them
}