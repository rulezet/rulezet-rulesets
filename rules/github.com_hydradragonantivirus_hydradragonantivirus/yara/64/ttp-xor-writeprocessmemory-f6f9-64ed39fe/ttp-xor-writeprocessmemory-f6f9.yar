rule TTP_XOR_WriteProcessMemory_f6f9 {
  strings:
    $key_f6f9 = { a1 8b [2] 93 a9 [2] 95 9c [2] bb 9c [2] 84 80 }

  condition:
    any of them
}