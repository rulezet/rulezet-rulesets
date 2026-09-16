rule TTP_XOR_WriteProcessMemory_3181 {
  strings:
    $key_3181 = { 66 f3 [2] 54 d1 [2] 52 e4 [2] 7c e4 [2] 43 f8 }

  condition:
    any of them
}