rule TTP_XOR_WriteProcessMemory_bb62 {
  strings:
    $key_bb62 = { ec 10 [2] de 32 [2] d8 07 [2] f6 07 [2] c9 1b }

  condition:
    any of them
}