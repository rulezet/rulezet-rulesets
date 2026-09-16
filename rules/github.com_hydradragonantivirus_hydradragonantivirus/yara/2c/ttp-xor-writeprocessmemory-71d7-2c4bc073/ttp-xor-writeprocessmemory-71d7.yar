rule TTP_XOR_WriteProcessMemory_71d7 {
  strings:
    $key_71d7 = { 26 a5 [2] 14 87 [2] 12 b2 [2] 3c b2 [2] 03 ae }

  condition:
    any of them
}