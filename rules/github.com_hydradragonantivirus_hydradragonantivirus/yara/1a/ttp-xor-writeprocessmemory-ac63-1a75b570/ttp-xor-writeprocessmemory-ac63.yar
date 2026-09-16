rule TTP_XOR_WriteProcessMemory_ac63 {
  strings:
    $key_ac63 = { fb 11 [2] c9 33 [2] cf 06 [2] e1 06 [2] de 1a }

  condition:
    any of them
}