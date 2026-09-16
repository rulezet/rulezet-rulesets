rule TTP_XOR_WriteProcessMemory_7181 {
  strings:
    $key_7181 = { 26 f3 [2] 14 d1 [2] 12 e4 [2] 3c e4 [2] 03 f8 }

  condition:
    any of them
}