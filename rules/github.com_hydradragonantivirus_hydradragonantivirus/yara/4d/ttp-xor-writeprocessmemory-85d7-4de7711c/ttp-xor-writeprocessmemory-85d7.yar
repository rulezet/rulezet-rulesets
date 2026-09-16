rule TTP_XOR_WriteProcessMemory_85d7 {
  strings:
    $key_85d7 = { d2 a5 [2] e0 87 [2] e6 b2 [2] c8 b2 [2] f7 ae }

  condition:
    any of them
}