rule TTP_XOR_WriteProcessMemory_8202 {
  strings:
    $key_8202 = { d5 70 [2] e7 52 [2] e1 67 [2] cf 67 [2] f0 7b }

  condition:
    any of them
}