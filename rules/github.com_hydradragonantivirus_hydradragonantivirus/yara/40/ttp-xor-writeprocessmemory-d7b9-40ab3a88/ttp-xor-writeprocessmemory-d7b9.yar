rule TTP_XOR_WriteProcessMemory_d7b9 {
  strings:
    $key_d7b9 = { 80 cb [2] b2 e9 [2] b4 dc [2] 9a dc [2] a5 c0 }

  condition:
    any of them
}