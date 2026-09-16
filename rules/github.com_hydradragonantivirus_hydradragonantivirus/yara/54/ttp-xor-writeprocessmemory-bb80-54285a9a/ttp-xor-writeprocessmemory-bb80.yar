rule TTP_XOR_WriteProcessMemory_bb80 {
  strings:
    $key_bb80 = { ec f2 [2] de d0 [2] d8 e5 [2] f6 e5 [2] c9 f9 }

  condition:
    any of them
}