rule TTP_XOR_WriteProcessMemory_ac65 {
  strings:
    $key_ac65 = { fb 17 [2] c9 35 [2] cf 00 [2] e1 00 [2] de 1c }

  condition:
    any of them
}