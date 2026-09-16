rule TTP_XOR_WriteProcessMemory_66d7 {
  strings:
    $key_66d7 = { 31 a5 [2] 03 87 [2] 05 b2 [2] 2b b2 [2] 14 ae }

  condition:
    any of them
}