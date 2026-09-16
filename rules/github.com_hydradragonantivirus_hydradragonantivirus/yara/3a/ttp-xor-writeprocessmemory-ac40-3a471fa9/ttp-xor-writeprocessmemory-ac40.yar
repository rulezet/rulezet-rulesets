rule TTP_XOR_WriteProcessMemory_ac40 {
  strings:
    $key_ac40 = { fb 32 [2] c9 10 [2] cf 25 [2] e1 25 [2] de 39 }

  condition:
    any of them
}