rule TTP_XOR_WriteProcessMemory_d1b9 {
  strings:
    $key_d1b9 = { 86 cb [2] b4 e9 [2] b2 dc [2] 9c dc [2] a3 c0 }

  condition:
    any of them
}