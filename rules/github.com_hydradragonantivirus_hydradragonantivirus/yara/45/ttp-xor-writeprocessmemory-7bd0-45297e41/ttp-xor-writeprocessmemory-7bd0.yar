rule TTP_XOR_WriteProcessMemory_7bd0 {
  strings:
    $key_7bd0 = { 2c a2 [2] 1e 80 [2] 18 b5 [2] 36 b5 [2] 09 a9 }

  condition:
    any of them
}