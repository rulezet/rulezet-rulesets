rule TTP_XOR_WriteProcessMemory_7243 {
  strings:
    $key_7243 = { 25 31 [2] 17 13 [2] 11 26 [2] 3f 26 [2] 00 3a }

  condition:
    any of them
}