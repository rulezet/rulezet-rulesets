rule TTP_XOR_WriteProcessMemory_3b92 {
  strings:
    $key_3b92 = { 6c e0 [2] 5e c2 [2] 58 f7 [2] 76 f7 [2] 49 eb }

  condition:
    any of them
}