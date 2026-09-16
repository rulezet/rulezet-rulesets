rule TTP_XOR_WriteProcessMemory_1856 {
  strings:
    $key_1856 = { 4f 24 [2] 7d 06 [2] 7b 33 [2] 55 33 [2] 6a 2f }

  condition:
    any of them
}