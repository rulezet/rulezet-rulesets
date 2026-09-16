rule TTP_XOR_WriteProcessMemory_ac43 {
  strings:
    $key_ac43 = { fb 31 [2] c9 13 [2] cf 26 [2] e1 26 [2] de 3a }

  condition:
    any of them
}