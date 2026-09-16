rule TTP_XOR_WriteProcessMemory_bb17 {
  strings:
    $key_bb17 = { ec 65 [2] de 47 [2] d8 72 [2] f6 72 [2] c9 6e }

  condition:
    any of them
}