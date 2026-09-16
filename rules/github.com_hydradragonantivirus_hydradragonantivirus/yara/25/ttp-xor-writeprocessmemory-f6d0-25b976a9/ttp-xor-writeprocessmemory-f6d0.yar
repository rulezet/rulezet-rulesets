rule TTP_XOR_WriteProcessMemory_f6d0 {
  strings:
    $key_f6d0 = { a1 a2 [2] 93 80 [2] 95 b5 [2] bb b5 [2] 84 a9 }

  condition:
    any of them
}