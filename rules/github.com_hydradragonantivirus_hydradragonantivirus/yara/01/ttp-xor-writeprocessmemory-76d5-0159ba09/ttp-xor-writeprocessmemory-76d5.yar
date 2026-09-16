rule TTP_XOR_WriteProcessMemory_76d5 {
  strings:
    $key_76d5 = { 21 a7 [2] 13 85 [2] 15 b0 [2] 3b b0 [2] 04 ac }

  condition:
    any of them
}