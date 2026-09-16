rule TTP_XOR_WriteProcessMemory_2d56 {
  strings:
    $key_2d56 = { 7a 24 [2] 48 06 [2] 4e 33 [2] 60 33 [2] 5f 2f }

  condition:
    any of them
}