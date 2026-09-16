rule TTP_XOR_WriteProcessMemory_f2c5 {
  strings:
    $key_f2c5 = { a5 b7 [2] 97 95 [2] 91 a0 [2] bf a0 [2] 80 bc }

  condition:
    any of them
}