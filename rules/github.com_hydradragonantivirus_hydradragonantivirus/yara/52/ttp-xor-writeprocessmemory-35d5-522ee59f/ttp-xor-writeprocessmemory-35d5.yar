rule TTP_XOR_WriteProcessMemory_35d5 {
  strings:
    $key_35d5 = { 62 a7 [2] 50 85 [2] 56 b0 [2] 78 b0 [2] 47 ac }

  condition:
    any of them
}