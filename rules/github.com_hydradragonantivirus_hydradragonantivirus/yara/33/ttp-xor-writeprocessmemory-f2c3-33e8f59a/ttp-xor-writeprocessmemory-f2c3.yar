rule TTP_XOR_WriteProcessMemory_f2c3 {
  strings:
    $key_f2c3 = { a5 b1 [2] 97 93 [2] 91 a6 [2] bf a6 [2] 80 ba }

  condition:
    any of them
}