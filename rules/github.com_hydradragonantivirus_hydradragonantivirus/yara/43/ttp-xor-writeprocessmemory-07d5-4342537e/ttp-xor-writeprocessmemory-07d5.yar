rule TTP_XOR_WriteProcessMemory_07d5 {
  strings:
    $key_07d5 = { 50 a7 [2] 62 85 [2] 64 b0 [2] 4a b0 [2] 75 ac }

  condition:
    any of them
}