rule TTP_XOR_WriteProcessMemory_4d56 {
  strings:
    $key_4d56 = { 1a 24 [2] 28 06 [2] 2e 33 [2] 00 33 [2] 3f 2f }

  condition:
    any of them
}