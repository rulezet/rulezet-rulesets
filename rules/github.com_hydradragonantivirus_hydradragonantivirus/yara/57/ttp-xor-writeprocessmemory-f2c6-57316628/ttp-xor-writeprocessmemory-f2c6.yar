rule TTP_XOR_WriteProcessMemory_f2c6 {
  strings:
    $key_f2c6 = { a5 b4 [2] 97 96 [2] 91 a3 [2] bf a3 [2] 80 bf }

  condition:
    any of them
}