rule TTP_XOR_WriteProcessMemory_c5b9 {
  strings:
    $key_c5b9 = { 92 cb [2] a0 e9 [2] a6 dc [2] 88 dc [2] b7 c0 }

  condition:
    any of them
}