rule TTP_XOR_WriteProcessMemory_ac33 {
  strings:
    $key_ac33 = { fb 41 [2] c9 63 [2] cf 56 [2] e1 56 [2] de 4a }

  condition:
    any of them
}