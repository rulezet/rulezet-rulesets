rule TTP_XOR_WriteProcessMemory_37d7 {
  strings:
    $key_37d7 = { 60 a5 [2] 52 87 [2] 54 b2 [2] 7a b2 [2] 45 ae }

  condition:
    any of them
}