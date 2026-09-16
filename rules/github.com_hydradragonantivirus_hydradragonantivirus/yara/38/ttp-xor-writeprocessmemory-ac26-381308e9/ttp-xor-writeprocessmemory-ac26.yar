rule TTP_XOR_WriteProcessMemory_ac26 {
  strings:
    $key_ac26 = { fb 54 [2] c9 76 [2] cf 43 [2] e1 43 [2] de 5f }

  condition:
    any of them
}