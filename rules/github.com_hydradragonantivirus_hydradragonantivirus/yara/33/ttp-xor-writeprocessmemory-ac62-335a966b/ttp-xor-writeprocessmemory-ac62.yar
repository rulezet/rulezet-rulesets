rule TTP_XOR_WriteProcessMemory_ac62 {
  strings:
    $key_ac62 = { fb 10 [2] c9 32 [2] cf 07 [2] e1 07 [2] de 1b }

  condition:
    any of them
}