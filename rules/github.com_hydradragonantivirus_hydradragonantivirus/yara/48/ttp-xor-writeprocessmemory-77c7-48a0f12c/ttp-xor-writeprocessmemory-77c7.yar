rule TTP_XOR_WriteProcessMemory_77c7 {
  strings:
    $key_77c7 = { 20 b5 [2] 12 97 [2] 14 a2 [2] 3a a2 [2] 05 be }

  condition:
    any of them
}