rule TTP_XOR_WriteProcessMemory_bb55 {
  strings:
    $key_bb55 = { ec 27 [2] de 05 [2] d8 30 [2] f6 30 [2] c9 2c }

  condition:
    any of them
}