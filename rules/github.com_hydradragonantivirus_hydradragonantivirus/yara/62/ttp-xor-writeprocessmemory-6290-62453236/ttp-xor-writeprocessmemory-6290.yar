rule TTP_XOR_WriteProcessMemory_6290 {
  strings:
    $key_6290 = { 35 e2 [2] 07 c0 [2] 01 f5 [2] 2f f5 [2] 10 e9 }

  condition:
    any of them
}