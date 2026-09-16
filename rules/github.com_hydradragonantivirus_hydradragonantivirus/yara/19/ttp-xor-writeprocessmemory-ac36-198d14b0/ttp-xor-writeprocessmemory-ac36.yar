rule TTP_XOR_WriteProcessMemory_ac36 {
  strings:
    $key_ac36 = { fb 44 [2] c9 66 [2] cf 53 [2] e1 53 [2] de 4f }

  condition:
    any of them
}