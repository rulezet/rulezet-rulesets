rule TTP_XOR_WriteProcessMemory_bb29 {
  strings:
    $key_bb29 = { ec 5b [2] de 79 [2] d8 4c [2] f6 4c [2] c9 50 }

  condition:
    any of them
}