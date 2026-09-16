rule TTP_XOR_WriteProcessMemory_c996 {
  strings:
    $key_c996 = { 9e e4 [2] ac c6 [2] aa f3 [2] 84 f3 [2] bb ef }

  condition:
    any of them
}