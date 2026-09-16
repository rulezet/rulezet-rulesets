rule TTP_XOR_WriteProcessMemory_c992 {
  strings:
    $key_c992 = { 9e e0 [2] ac c2 [2] aa f7 [2] 84 f7 [2] bb eb }

  condition:
    any of them
}