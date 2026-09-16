rule TTP_XOR_WriteProcessMemory_bb22 {
  strings:
    $key_bb22 = { ec 50 [2] de 72 [2] d8 47 [2] f6 47 [2] c9 5b }

  condition:
    any of them
}