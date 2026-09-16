rule TTP_XOR_WriteProcessMemory_f2d7 {
  strings:
    $key_f2d7 = { a5 a5 [2] 97 87 [2] 91 b2 [2] bf b2 [2] 80 ae }

  condition:
    any of them
}