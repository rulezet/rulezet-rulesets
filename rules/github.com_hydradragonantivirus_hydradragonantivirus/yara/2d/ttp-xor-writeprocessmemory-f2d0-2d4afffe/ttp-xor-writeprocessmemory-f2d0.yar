rule TTP_XOR_WriteProcessMemory_f2d0 {
  strings:
    $key_f2d0 = { a5 a2 [2] 97 80 [2] 91 b5 [2] bf b5 [2] 80 a9 }

  condition:
    any of them
}