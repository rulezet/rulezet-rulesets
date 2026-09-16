rule TTP_XOR_WriteProcessMemory_f6d9 {
  strings:
    $key_f6d9 = { a1 ab [2] 93 89 [2] 95 bc [2] bb bc [2] 84 a0 }

  condition:
    any of them
}