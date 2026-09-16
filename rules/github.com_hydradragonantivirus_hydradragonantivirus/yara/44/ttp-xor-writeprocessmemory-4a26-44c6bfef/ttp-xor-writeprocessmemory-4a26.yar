rule TTP_XOR_WriteProcessMemory_4a26 {
  strings:
    $key_4a26 = { 1d 54 [2] 2f 76 [2] 29 43 [2] 07 43 [2] 38 5f }

  condition:
    any of them
}