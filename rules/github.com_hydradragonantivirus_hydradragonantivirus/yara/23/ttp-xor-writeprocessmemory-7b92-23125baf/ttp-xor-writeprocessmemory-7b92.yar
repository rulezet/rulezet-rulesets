rule TTP_XOR_WriteProcessMemory_7b92 {
  strings:
    $key_7b92 = { 2c e0 [2] 1e c2 [2] 18 f7 [2] 36 f7 [2] 09 eb }

  condition:
    any of them
}