rule TTP_XOR_WriteProcessMemory_6bd7 {
  strings:
    $key_6bd7 = { 3c a5 [2] 0e 87 [2] 08 b2 [2] 26 b2 [2] 19 ae }

  condition:
    any of them
}