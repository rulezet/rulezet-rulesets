rule TTP_XOR_WriteProcessMemory_7391 {
  strings:
    $key_7391 = { 24 e3 [2] 16 c1 [2] 10 f4 [2] 3e f4 [2] 01 e8 }

  condition:
    any of them
}