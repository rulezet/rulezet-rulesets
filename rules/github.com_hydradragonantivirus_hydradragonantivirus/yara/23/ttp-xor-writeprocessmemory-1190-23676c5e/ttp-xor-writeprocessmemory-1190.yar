rule TTP_XOR_WriteProcessMemory_1190 {
  strings:
    $key_1190 = { 46 e2 [2] 74 c0 [2] 72 f5 [2] 5c f5 [2] 63 e9 }

  condition:
    any of them
}