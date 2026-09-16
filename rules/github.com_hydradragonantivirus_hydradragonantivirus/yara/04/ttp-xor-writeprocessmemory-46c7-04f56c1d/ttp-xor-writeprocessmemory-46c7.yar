rule TTP_XOR_WriteProcessMemory_46c7 {
  strings:
    $key_46c7 = { 11 b5 [2] 23 97 [2] 25 a2 [2] 0b a2 [2] 34 be }

  condition:
    any of them
}