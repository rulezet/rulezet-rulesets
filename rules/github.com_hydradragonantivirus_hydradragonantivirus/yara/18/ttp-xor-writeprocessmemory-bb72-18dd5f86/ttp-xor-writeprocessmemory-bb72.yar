rule TTP_XOR_WriteProcessMemory_bb72 {
  strings:
    $key_bb72 = { ec 00 [2] de 22 [2] d8 17 [2] f6 17 [2] c9 0b }

  condition:
    any of them
}