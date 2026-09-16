rule TTP_XOR_WriteProcessMemory_3bd7 {
  strings:
    $key_3bd7 = { 6c a5 [2] 5e 87 [2] 58 b2 [2] 76 b2 [2] 49 ae }

  condition:
    any of them
}