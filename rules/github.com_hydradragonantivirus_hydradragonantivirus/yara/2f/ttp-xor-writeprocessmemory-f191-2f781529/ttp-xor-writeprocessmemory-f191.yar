rule TTP_XOR_WriteProcessMemory_f191 {
  strings:
    $key_f191 = { a6 e3 [2] 94 c1 [2] 92 f4 [2] bc f4 [2] 83 e8 }

  condition:
    any of them
}