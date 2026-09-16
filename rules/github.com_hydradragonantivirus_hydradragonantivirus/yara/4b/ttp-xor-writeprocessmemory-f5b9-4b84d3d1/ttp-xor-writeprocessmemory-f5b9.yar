rule TTP_XOR_WriteProcessMemory_f5b9 {
  strings:
    $key_f5b9 = { a2 cb [2] 90 e9 [2] 96 dc [2] b8 dc [2] 87 c0 }

  condition:
    any of them
}