rule TTP_XOR_WriteProcessMemory_bb65 {
  strings:
    $key_bb65 = { ec 17 [2] de 35 [2] d8 00 [2] f6 00 [2] c9 1c }

  condition:
    any of them
}