rule TTP_XOR_WriteProcessMemory_f194 {
  strings:
    $key_f194 = { a6 e6 [2] 94 c4 [2] 92 f1 [2] bc f1 [2] 83 ed }

  condition:
    any of them
}