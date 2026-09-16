rule TTP_XOR_WriteProcessMemory_bd85 {
  strings:
    $key_bd85 = { ea f7 [2] d8 d5 [2] de e0 [2] f0 e0 [2] cf fc }

  condition:
    any of them
}