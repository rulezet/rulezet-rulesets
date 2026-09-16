rule TTP_XOR_WriteProcessMemory_7290 {
  strings:
    $key_7290 = { 25 e2 [2] 17 c0 [2] 11 f5 [2] 3f f5 [2] 00 e9 }

  condition:
    any of them
}