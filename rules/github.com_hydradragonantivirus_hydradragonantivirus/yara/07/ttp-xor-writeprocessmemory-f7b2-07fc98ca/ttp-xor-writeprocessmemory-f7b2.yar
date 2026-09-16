rule TTP_XOR_WriteProcessMemory_f7b2 {
  strings:
    $key_f7b2 = { a0 c0 [2] 92 e2 [2] 94 d7 [2] ba d7 [2] 85 cb }

  condition:
    any of them
}