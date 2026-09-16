rule TTP_XOR_WriteProcessMemory_f691 {
  strings:
    $key_f691 = { a1 e3 [2] 93 c1 [2] 95 f4 [2] bb f4 [2] 84 e8 }

  condition:
    any of them
}