rule TTP_XOR_WriteProcessMemory_ac70 {
  strings:
    $key_ac70 = { fb 02 [2] c9 20 [2] cf 15 [2] e1 15 [2] de 09 }

  condition:
    any of them
}