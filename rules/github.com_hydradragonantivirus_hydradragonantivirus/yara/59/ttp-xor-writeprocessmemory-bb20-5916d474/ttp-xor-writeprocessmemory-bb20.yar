rule TTP_XOR_WriteProcessMemory_bb20 {
  strings:
    $key_bb20 = { ec 52 [2] de 70 [2] d8 45 [2] f6 45 [2] c9 59 }

  condition:
    any of them
}