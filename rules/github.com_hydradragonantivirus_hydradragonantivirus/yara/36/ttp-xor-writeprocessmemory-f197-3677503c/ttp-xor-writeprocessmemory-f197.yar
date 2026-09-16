rule TTP_XOR_WriteProcessMemory_f197 {
  strings:
    $key_f197 = { a6 e5 [2] 94 c7 [2] 92 f2 [2] bc f2 [2] 83 ee }

  condition:
    any of them
}