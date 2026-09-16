rule TTP_XOR_WriteProcessMemory_bb12 {
  strings:
    $key_bb12 = { ec 60 [2] de 42 [2] d8 77 [2] f6 77 [2] c9 6b }

  condition:
    any of them
}