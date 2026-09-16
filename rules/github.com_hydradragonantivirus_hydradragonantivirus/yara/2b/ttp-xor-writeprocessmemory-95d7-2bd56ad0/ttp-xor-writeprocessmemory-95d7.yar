rule TTP_XOR_WriteProcessMemory_95d7 {
  strings:
    $key_95d7 = { c2 a5 [2] f0 87 [2] f6 b2 [2] d8 b2 [2] e7 ae }

  condition:
    any of them
}