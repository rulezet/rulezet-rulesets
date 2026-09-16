rule TTP_XOR_WriteProcessMemory_75c7 {
  strings:
    $key_75c7 = { 22 b5 [2] 10 97 [2] 16 a2 [2] 38 a2 [2] 07 be }

  condition:
    any of them
}