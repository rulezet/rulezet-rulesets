rule TTP_XOR_WriteProcessMemory_65c7 {
  strings:
    $key_65c7 = { 32 b5 [2] 00 97 [2] 06 a2 [2] 28 a2 [2] 17 be }

  condition:
    any of them
}