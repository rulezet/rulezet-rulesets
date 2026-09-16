rule TTP_XOR_WriteProcessMemory_4a56 {
  strings:
    $key_4a56 = { 1d 24 [2] 2f 06 [2] 29 33 [2] 07 33 [2] 38 2f }

  condition:
    any of them
}