rule TTP_XOR_WriteProcessMemory_c2b9 {
  strings:
    $key_c2b9 = { 95 cb [2] a7 e9 [2] a1 dc [2] 8f dc [2] b0 c0 }

  condition:
    any of them
}