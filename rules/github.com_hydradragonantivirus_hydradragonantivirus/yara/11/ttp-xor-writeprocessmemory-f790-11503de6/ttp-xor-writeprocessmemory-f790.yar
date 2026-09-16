rule TTP_XOR_WriteProcessMemory_f790 {
  strings:
    $key_f790 = { a0 e2 [2] 92 c0 [2] 94 f5 [2] ba f5 [2] 85 e9 }

  condition:
    any of them
}