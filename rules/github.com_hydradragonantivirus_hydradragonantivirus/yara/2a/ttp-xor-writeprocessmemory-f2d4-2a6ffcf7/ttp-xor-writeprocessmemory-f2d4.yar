rule TTP_XOR_WriteProcessMemory_f2d4 {
  strings:
    $key_f2d4 = { a5 a6 [2] 97 84 [2] 91 b1 [2] bf b1 [2] 80 ad }

  condition:
    any of them
}