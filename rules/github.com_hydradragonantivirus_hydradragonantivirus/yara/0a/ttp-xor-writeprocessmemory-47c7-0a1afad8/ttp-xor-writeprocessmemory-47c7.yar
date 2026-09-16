rule TTP_XOR_WriteProcessMemory_47c7 {
  strings:
    $key_47c7 = { 10 b5 [2] 22 97 [2] 24 a2 [2] 0a a2 [2] 35 be }

  condition:
    any of them
}