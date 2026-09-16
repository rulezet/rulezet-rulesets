rule TTP_XOR_WriteProcessMemory_bb52 {
  strings:
    $key_bb52 = { ec 20 [2] de 02 [2] d8 37 [2] f6 37 [2] c9 2b }

  condition:
    any of them
}