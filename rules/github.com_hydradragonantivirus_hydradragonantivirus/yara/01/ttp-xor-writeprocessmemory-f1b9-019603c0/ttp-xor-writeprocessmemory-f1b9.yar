rule TTP_XOR_WriteProcessMemory_f1b9 {
  strings:
    $key_f1b9 = { a6 cb [2] 94 e9 [2] 92 dc [2] bc dc [2] 83 c0 }

  condition:
    any of them
}