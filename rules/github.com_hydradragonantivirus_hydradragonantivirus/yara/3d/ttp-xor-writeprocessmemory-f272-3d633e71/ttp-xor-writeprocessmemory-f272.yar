rule TTP_XOR_WriteProcessMemory_f272 {
  strings:
    $key_f272 = { a5 00 [2] 97 22 [2] 91 17 [2] bf 17 [2] 80 0b }

  condition:
    any of them
}