rule TTP_XOR_WriteProcessMemory_f6c3 {
  strings:
    $key_f6c3 = { a1 b1 [2] 93 93 [2] 95 a6 [2] bb a6 [2] 84 ba }

  condition:
    any of them
}