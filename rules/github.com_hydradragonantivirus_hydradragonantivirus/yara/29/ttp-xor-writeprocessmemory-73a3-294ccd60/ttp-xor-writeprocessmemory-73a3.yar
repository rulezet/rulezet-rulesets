rule TTP_XOR_WriteProcessMemory_73a3 {
  strings:
    $key_73a3 = { 24 d1 [2] 16 f3 [2] 10 c6 [2] 3e c6 [2] 01 da }

  condition:
    any of them
}