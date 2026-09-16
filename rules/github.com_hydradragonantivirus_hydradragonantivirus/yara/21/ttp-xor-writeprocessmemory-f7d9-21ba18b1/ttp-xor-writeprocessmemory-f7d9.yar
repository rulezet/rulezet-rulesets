rule TTP_XOR_WriteProcessMemory_f7d9 {
  strings:
    $key_f7d9 = { a0 ab [2] 92 89 [2] 94 bc [2] ba bc [2] 85 a0 }

  condition:
    any of them
}