rule TTP_XOR_WriteProcessMemory_74d7 {
  strings:
    $key_74d7 = { 23 a5 [2] 11 87 [2] 17 b2 [2] 39 b2 [2] 06 ae }

  condition:
    any of them
}