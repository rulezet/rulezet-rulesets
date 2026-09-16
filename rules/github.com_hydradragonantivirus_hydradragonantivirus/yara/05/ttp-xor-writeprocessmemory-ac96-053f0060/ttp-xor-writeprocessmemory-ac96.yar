rule TTP_XOR_WriteProcessMemory_ac96 {
  strings:
    $key_ac96 = { fb e4 [2] c9 c6 [2] cf f3 [2] e1 f3 [2] de ef }

  condition:
    any of them
}