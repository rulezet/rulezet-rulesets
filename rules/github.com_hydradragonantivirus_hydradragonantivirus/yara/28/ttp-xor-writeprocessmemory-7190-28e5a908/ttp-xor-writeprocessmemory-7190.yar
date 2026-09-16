rule TTP_XOR_WriteProcessMemory_7190 {
  strings:
    $key_7190 = { 26 e2 [2] 14 c0 [2] 12 f5 [2] 3c f5 [2] 03 e9 }

  condition:
    any of them
}