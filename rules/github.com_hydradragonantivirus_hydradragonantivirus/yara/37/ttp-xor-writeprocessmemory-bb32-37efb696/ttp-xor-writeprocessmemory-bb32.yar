rule TTP_XOR_WriteProcessMemory_bb32 {
  strings:
    $key_bb32 = { ec 40 [2] de 62 [2] d8 57 [2] f6 57 [2] c9 4b }

  condition:
    any of them
}