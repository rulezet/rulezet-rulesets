rule TTP_XOR_WriteProcessMemory_f485 {
  strings:
    $key_f485 = { a3 f7 [2] 91 d5 [2] 97 e0 [2] b9 e0 [2] 86 fc }

  condition:
    any of them
}