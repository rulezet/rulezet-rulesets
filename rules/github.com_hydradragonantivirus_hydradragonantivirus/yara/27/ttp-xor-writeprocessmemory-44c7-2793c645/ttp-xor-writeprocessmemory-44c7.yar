rule TTP_XOR_WriteProcessMemory_44c7 {
  strings:
    $key_44c7 = { 13 b5 [2] 21 97 [2] 27 a2 [2] 09 a2 [2] 36 be }

  condition:
    any of them
}