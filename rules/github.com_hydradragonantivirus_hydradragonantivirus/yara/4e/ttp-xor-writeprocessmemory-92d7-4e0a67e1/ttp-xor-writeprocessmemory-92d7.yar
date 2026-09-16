rule TTP_XOR_WriteProcessMemory_92d7 {
  strings:
    $key_92d7 = { c5 a5 [2] f7 87 [2] f1 b2 [2] df b2 [2] e0 ae }

  condition:
    any of them
}