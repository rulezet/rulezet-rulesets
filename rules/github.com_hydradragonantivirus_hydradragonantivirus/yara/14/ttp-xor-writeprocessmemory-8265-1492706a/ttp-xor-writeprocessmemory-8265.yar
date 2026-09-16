rule TTP_XOR_WriteProcessMemory_8265 {
  strings:
    $key_8265 = { d5 17 [2] e7 35 [2] e1 00 [2] cf 00 [2] f0 1c }

  condition:
    any of them
}