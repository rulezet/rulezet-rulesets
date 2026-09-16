rule TTP_XOR_WriteProcessMemory_ac50 {
  strings:
    $key_ac50 = { fb 22 [2] c9 00 [2] cf 35 [2] e1 35 [2] de 29 }

  condition:
    any of them
}