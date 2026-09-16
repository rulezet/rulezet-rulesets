rule TTP_XOR_WriteProcessMemory_bb43 {
  strings:
    $key_bb43 = { ec 31 [2] de 13 [2] d8 26 [2] f6 26 [2] c9 3a }

  condition:
    any of them
}