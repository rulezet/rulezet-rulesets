rule TTP_XOR_WriteProcessMemory_ac72 {
  strings:
    $key_ac72 = { fb 00 [2] c9 22 [2] cf 17 [2] e1 17 [2] de 0b }

  condition:
    any of them
}