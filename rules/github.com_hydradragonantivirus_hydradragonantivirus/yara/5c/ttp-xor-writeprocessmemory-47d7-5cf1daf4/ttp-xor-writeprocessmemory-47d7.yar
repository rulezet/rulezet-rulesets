rule TTP_XOR_WriteProcessMemory_47d7 {
  strings:
    $key_47d7 = { 10 a5 [2] 22 87 [2] 24 b2 [2] 0a b2 [2] 35 ae }

  condition:
    any of them
}