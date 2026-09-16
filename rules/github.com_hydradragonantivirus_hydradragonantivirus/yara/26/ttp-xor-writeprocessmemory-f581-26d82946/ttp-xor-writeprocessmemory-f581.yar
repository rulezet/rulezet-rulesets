rule TTP_XOR_WriteProcessMemory_f581 {
  strings:
    $key_f581 = { a2 f3 [2] 90 d1 [2] 96 e4 [2] b8 e4 [2] 87 f8 }

  condition:
    any of them
}