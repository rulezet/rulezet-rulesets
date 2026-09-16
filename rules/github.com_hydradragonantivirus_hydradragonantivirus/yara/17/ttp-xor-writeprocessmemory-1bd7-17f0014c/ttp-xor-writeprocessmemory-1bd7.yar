rule TTP_XOR_WriteProcessMemory_1bd7 {
  strings:
    $key_1bd7 = { 4c a5 [2] 7e 87 [2] 78 b2 [2] 56 b2 [2] 69 ae }

  condition:
    any of them
}