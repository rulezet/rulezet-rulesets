rule TTP_XOR_WriteProcessMemory_bbdd {
  strings:
    $key_bbdd = { ec af [2] de 8d [2] d8 b8 [2] f6 b8 [2] c9 a4 }

  condition:
    any of them
}