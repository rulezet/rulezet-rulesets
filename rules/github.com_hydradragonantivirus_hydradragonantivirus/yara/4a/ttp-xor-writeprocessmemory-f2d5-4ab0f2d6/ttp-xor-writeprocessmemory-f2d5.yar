rule TTP_XOR_WriteProcessMemory_f2d5 {
  strings:
    $key_f2d5 = { a5 a7 [2] 97 85 [2] 91 b0 [2] bf b0 [2] 80 ac }

  condition:
    any of them
}