rule TTP_XOR_WriteProcessMemory_f6b3 {
  strings:
    $key_f6b3 = { a1 c1 [2] 93 e3 [2] 95 d6 [2] bb d6 [2] 84 ca }

  condition:
    any of them
}