rule TTP_XOR_WriteProcessMemory_f6e9 {
  strings:
    $key_f6e9 = { a1 9b [2] 93 b9 [2] 95 8c [2] bb 8c [2] 84 90 }

  condition:
    any of them
}