rule TTP_XOR_WriteProcessMemory_72d7 {
  strings:
    $key_72d7 = { 25 a5 [2] 17 87 [2] 11 b2 [2] 3f b2 [2] 00 ae }

  condition:
    any of them
}