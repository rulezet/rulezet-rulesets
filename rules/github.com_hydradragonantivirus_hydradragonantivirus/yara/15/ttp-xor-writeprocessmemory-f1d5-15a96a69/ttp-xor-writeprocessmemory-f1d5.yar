rule TTP_XOR_WriteProcessMemory_f1d5 {
  strings:
    $key_f1d5 = { a6 a7 [2] 94 85 [2] 92 b0 [2] bc b0 [2] 83 ac }

  condition:
    any of them
}