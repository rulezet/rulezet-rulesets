rule TTP_XOR_WriteProcessMemory_56c7 {
  strings:
    $key_56c7 = { 01 b5 [2] 33 97 [2] 35 a2 [2] 1b a2 [2] 24 be }

  condition:
    any of them
}