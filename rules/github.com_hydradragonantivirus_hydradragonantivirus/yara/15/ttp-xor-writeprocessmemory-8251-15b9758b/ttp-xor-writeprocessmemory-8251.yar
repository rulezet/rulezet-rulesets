rule TTP_XOR_WriteProcessMemory_8251 {
  strings:
    $key_8251 = { d5 23 [2] e7 01 [2] e1 34 [2] cf 34 [2] f0 28 }

  condition:
    any of them
}