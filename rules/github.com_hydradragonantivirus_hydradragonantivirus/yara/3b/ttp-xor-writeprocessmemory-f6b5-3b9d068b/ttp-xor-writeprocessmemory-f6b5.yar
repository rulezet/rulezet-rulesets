rule TTP_XOR_WriteProcessMemory_f6b5 {
  strings:
    $key_f6b5 = { a1 c7 [2] 93 e5 [2] 95 d0 [2] bb d0 [2] 84 cc }

  condition:
    any of them
}