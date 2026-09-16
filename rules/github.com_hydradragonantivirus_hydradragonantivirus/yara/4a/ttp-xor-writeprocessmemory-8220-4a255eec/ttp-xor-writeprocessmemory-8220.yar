rule TTP_XOR_WriteProcessMemory_8220 {
  strings:
    $key_8220 = { d5 52 [2] e7 70 [2] e1 45 [2] cf 45 [2] f0 59 }

  condition:
    any of them
}