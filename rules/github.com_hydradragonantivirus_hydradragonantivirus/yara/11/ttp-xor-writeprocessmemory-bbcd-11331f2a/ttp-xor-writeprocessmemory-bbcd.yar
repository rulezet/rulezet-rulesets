rule TTP_XOR_WriteProcessMemory_bbcd {
  strings:
    $key_bbcd = { ec bf [2] de 9d [2] d8 a8 [2] f6 a8 [2] c9 b4 }

  condition:
    any of them
}