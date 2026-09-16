rule TTP_XOR_WriteProcessMemory_bd87 {
  strings:
    $key_bd87 = { ea f5 [2] d8 d7 [2] de e2 [2] f0 e2 [2] cf fe }

  condition:
    any of them
}