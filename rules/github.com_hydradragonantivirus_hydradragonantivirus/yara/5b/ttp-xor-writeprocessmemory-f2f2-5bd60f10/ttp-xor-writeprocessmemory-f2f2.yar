rule TTP_XOR_WriteProcessMemory_f2f2 {
  strings:
    $key_f2f2 = { a5 80 [2] 97 a2 [2] 91 97 [2] bf 97 [2] 80 8b }

  condition:
    any of them
}