rule TTP_XOR_WriteProcessMemory_e4b9 {
  strings:
    $key_e4b9 = { b3 cb [2] 81 e9 [2] 87 dc [2] a9 dc [2] 96 c0 }

  condition:
    any of them
}