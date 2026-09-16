rule TTP_XOR_WriteProcessMemory_bbd0 {
  strings:
    $key_bbd0 = { ec a2 [2] de 80 [2] d8 b5 [2] f6 b5 [2] c9 a9 }

  condition:
    any of them
}