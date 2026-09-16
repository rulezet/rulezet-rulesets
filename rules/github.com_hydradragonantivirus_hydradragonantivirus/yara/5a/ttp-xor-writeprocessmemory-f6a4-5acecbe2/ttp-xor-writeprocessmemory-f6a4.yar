rule TTP_XOR_WriteProcessMemory_f6a4 {
  strings:
    $key_f6a4 = { a1 d6 [2] 93 f4 [2] 95 c1 [2] bb c1 [2] 84 dd }

  condition:
    any of them
}