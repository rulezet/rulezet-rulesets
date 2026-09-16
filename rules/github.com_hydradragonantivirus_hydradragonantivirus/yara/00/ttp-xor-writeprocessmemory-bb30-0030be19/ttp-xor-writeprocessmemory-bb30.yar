rule TTP_XOR_WriteProcessMemory_bb30 {
  strings:
    $key_bb30 = { ec 42 [2] de 60 [2] d8 55 [2] f6 55 [2] c9 49 }

  condition:
    any of them
}