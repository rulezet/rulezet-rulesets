rule TTP_XOR_WriteProcessMemory_f285 {
  strings:
    $key_f285 = { a5 f7 [2] 97 d5 [2] 91 e0 [2] bf e0 [2] 80 fc }

  condition:
    any of them
}