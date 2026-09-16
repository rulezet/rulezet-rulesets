rule TTP_XOR_WriteProcessMemory_ac95 {
  strings:
    $key_ac95 = { fb e7 [2] c9 c5 [2] cf f0 [2] e1 f0 [2] de ec }

  condition:
    any of them
}