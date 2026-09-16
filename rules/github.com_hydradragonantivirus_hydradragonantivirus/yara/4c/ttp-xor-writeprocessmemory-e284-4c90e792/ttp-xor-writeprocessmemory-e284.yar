rule TTP_XOR_WriteProcessMemory_e284 {
  strings:
    $key_e284 = { b5 f6 [2] 87 d4 [2] 81 e1 [2] af e1 [2] 90 fd }

  condition:
    any of them
}