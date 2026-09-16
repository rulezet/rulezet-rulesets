rule TTP_XOR_WriteProcessMemory_ac53 {
  strings:
    $key_ac53 = { fb 21 [2] c9 03 [2] cf 36 [2] e1 36 [2] de 2a }

  condition:
    any of them
}