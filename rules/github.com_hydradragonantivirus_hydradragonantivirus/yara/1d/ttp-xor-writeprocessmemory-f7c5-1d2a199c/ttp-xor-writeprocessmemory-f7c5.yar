rule TTP_XOR_WriteProcessMemory_f7c5 {
  strings:
    $key_f7c5 = { a0 b7 [2] 92 95 [2] 94 a0 [2] ba a0 [2] 85 bc }

  condition:
    any of them
}