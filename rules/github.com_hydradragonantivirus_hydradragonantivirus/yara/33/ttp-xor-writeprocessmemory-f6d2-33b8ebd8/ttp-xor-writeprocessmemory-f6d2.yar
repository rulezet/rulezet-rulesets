rule TTP_XOR_WriteProcessMemory_f6d2 {
  strings:
    $key_f6d2 = { a1 a0 [2] 93 82 [2] 95 b7 [2] bb b7 [2] 84 ab }

  condition:
    any of them
}