rule TTP_XOR_WriteProcessMemory_75d7 {
  strings:
    $key_75d7 = { 22 a5 [2] 10 87 [2] 16 b2 [2] 38 b2 [2] 07 ae }

  condition:
    any of them
}