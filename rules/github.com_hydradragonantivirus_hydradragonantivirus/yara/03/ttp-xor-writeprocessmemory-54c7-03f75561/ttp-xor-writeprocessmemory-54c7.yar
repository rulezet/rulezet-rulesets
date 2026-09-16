rule TTP_XOR_WriteProcessMemory_54c7 {
  strings:
    $key_54c7 = { 03 b5 [2] 31 97 [2] 37 a2 [2] 19 a2 [2] 26 be }

  condition:
    any of them
}