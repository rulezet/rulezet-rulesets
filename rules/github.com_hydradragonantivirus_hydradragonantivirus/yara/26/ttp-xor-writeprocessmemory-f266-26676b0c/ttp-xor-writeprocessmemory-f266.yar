rule TTP_XOR_WriteProcessMemory_f266 {
  strings:
    $key_f266 = { a5 14 [2] 97 36 [2] 91 03 [2] bf 03 [2] 80 1f }

  condition:
    any of them
}