rule TTP_XOR_WriteProcessMemory_f3b9 {
  strings:
    $key_f3b9 = { a4 cb [2] 96 e9 [2] 90 dc [2] be dc [2] 81 c0 }

  condition:
    any of them
}