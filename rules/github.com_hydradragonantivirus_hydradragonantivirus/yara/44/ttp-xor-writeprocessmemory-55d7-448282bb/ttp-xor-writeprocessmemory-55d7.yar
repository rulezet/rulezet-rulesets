rule TTP_XOR_WriteProcessMemory_55d7 {
  strings:
    $key_55d7 = { 02 a5 [2] 30 87 [2] 36 b2 [2] 18 b2 [2] 27 ae }

  condition:
    any of them
}