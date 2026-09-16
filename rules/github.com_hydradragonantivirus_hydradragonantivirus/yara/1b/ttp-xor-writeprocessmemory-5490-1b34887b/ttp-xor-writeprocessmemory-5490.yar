rule TTP_XOR_WriteProcessMemory_5490 {
  strings:
    $key_5490 = { 03 e2 [2] 31 c0 [2] 37 f5 [2] 19 f5 [2] 26 e9 }

  condition:
    any of them
}