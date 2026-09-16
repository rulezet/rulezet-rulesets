rule TTP_XOR_WriteProcessMemory_f226 {
  strings:
    $key_f226 = { a5 54 [2] 97 76 [2] 91 43 [2] bf 43 [2] 80 5f }

  condition:
    any of them
}