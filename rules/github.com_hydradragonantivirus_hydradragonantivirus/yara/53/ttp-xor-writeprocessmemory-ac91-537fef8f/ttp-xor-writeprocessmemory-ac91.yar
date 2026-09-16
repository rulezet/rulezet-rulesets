rule TTP_XOR_WriteProcessMemory_ac91 {
  strings:
    $key_ac91 = { fb e3 [2] c9 c1 [2] cf f4 [2] e1 f4 [2] de e8 }

  condition:
    any of them
}