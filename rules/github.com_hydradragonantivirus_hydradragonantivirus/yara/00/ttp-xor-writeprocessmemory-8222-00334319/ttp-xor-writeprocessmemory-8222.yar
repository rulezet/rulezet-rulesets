rule TTP_XOR_WriteProcessMemory_8222 {
  strings:
    $key_8222 = { d5 50 [2] e7 72 [2] e1 47 [2] cf 47 [2] f0 5b }

  condition:
    any of them
}