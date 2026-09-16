rule TTP_XOR_WriteProcessMemory_1790 {
  strings:
    $key_1790 = { 40 e2 [2] 72 c0 [2] 74 f5 [2] 5a f5 [2] 65 e9 }

  condition:
    any of them
}