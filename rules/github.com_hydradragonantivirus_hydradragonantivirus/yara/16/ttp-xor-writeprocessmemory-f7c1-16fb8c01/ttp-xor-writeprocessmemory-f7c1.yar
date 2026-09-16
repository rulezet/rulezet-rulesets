rule TTP_XOR_WriteProcessMemory_f7c1 {
  strings:
    $key_f7c1 = { a0 b3 [2] 92 91 [2] 94 a4 [2] ba a4 [2] 85 b8 }

  condition:
    any of them
}