rule TTP_XOR_WriteProcessMemory_f200 {
  strings:
    $key_f200 = { a5 72 [2] 97 50 [2] 91 65 [2] bf 65 [2] 80 79 }

  condition:
    any of them
}