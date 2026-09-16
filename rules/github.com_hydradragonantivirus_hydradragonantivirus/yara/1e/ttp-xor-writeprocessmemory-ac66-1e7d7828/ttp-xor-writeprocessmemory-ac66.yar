rule TTP_XOR_WriteProcessMemory_ac66 {
  strings:
    $key_ac66 = { fb 14 [2] c9 36 [2] cf 03 [2] e1 03 [2] de 1f }

  condition:
    any of them
}