rule TTP_XOR_WriteProcessMemory_d4b9 {
  strings:
    $key_d4b9 = { 83 cb [2] b1 e9 [2] b7 dc [2] 99 dc [2] a6 c0 }

  condition:
    any of them
}