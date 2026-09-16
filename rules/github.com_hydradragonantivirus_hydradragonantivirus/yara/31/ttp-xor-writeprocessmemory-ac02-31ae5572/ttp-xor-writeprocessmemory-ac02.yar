rule TTP_XOR_WriteProcessMemory_ac02 {
  strings:
    $key_ac02 = { fb 70 [2] c9 52 [2] cf 67 [2] e1 67 [2] de 7b }

  condition:
    any of them
}