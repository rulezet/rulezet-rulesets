rule TTP_XOR_WriteProcessMemory_ac90 {
  strings:
    $key_ac90 = { fb e2 [2] c9 c0 [2] cf f5 [2] e1 f5 [2] de e9 }

  condition:
    any of them
}