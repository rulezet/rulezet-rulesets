rule TTP_XOR_WriteProcessMemory_bb45 {
  strings:
    $key_bb45 = { ec 37 [2] de 15 [2] d8 20 [2] f6 20 [2] c9 3c }

  condition:
    any of them
}