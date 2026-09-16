rule TTP_XOR_WriteProcessMemory_f086 {
  strings:
    $key_f086 = { a7 f4 [2] 95 d6 [2] 93 e3 [2] bd e3 [2] 82 ff }

  condition:
    any of them
}