rule TTP_XOR_WriteProcessMemory_bbd1 {
  strings:
    $key_bbd1 = { ec a3 [2] de 81 [2] d8 b4 [2] f6 b4 [2] c9 a8 }

  condition:
    any of them
}