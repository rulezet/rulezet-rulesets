rule TTP_XOR_WriteProcessMemory_35d7 {
  strings:
    $key_35d7 = { 62 a5 [2] 50 87 [2] 56 b2 [2] 78 b2 [2] 47 ae }

  condition:
    any of them
}