rule TTP_XOR_WriteProcessMemory_bb63 {
  strings:
    $key_bb63 = { ec 11 [2] de 33 [2] d8 06 [2] f6 06 [2] c9 1a }

  condition:
    any of them
}