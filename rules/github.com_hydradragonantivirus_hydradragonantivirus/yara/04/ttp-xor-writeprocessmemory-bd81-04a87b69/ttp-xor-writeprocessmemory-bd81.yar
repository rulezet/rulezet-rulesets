rule TTP_XOR_WriteProcessMemory_bd81 {
  strings:
    $key_bd81 = { ea f3 [2] d8 d1 [2] de e4 [2] f0 e4 [2] cf f8 }

  condition:
    any of them
}