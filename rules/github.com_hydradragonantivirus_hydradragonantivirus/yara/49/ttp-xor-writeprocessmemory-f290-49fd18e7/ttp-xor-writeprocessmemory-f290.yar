rule TTP_XOR_WriteProcessMemory_f290 {
  strings:
    $key_f290 = { a5 e2 [2] 97 c0 [2] 91 f5 [2] bf f5 [2] 80 e9 }

  condition:
    any of them
}