rule TTP_XOR_WriteProcessMemory_1181 {
  strings:
    $key_1181 = { 46 f3 [2] 74 d1 [2] 72 e4 [2] 5c e4 [2] 63 f8 }

  condition:
    any of them
}