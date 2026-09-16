rule TTP_XOR_WriteProcessMemory_25c0 {
  strings:
    $key_25c0 = { 72 b2 [2] 40 90 [2] 46 a5 [2] 68 a5 [2] 57 b9 }

  condition:
    any of them
}