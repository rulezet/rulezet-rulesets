rule TTP_XOR_WriteProcessMemory_c3b9 {
  strings:
    $key_c3b9 = { 94 cb [2] a6 e9 [2] a0 dc [2] 8e dc [2] b1 c0 }

  condition:
    any of them
}