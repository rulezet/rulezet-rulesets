rule TTP_XOR_WriteProcessMemory_1c56 {
  strings:
    $key_1c56 = { 4b 24 [2] 79 06 [2] 7f 33 [2] 51 33 [2] 6e 2f }

  condition:
    any of them
}