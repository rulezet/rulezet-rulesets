rule TTP_XOR_WriteProcessMemory_bb41 {
  strings:
    $key_bb41 = { ec 33 [2] de 11 [2] d8 24 [2] f6 24 [2] c9 38 }

  condition:
    any of them
}