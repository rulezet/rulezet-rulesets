rule TTP_XOR_WriteProcessMemory_01d7 {
  strings:
    $key_01d7 = { 56 a5 [2] 64 87 [2] 62 b2 [2] 4c b2 [2] 73 ae }

  condition:
    any of them
}