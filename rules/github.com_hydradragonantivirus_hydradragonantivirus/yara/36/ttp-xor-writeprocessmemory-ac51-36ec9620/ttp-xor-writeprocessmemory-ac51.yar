rule TTP_XOR_WriteProcessMemory_ac51 {
  strings:
    $key_ac51 = { fb 23 [2] c9 01 [2] cf 34 [2] e1 34 [2] de 28 }

  condition:
    any of them
}