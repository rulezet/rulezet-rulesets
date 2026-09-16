rule TTP_XOR_WriteProcessMemory_c1b9 {
  strings:
    $key_c1b9 = { 96 cb [2] a4 e9 [2] a2 dc [2] 8c dc [2] b3 c0 }

  condition:
    any of them
}