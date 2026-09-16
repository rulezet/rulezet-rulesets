rule TTP_XOR_WriteProcessMemory_ac60 {
  strings:
    $key_ac60 = { fb 12 [2] c9 30 [2] cf 05 [2] e1 05 [2] de 19 }

  condition:
    any of them
}