rule TTP_XOR_WriteProcessMemory_f2f1 {
  strings:
    $key_f2f1 = { a5 83 [2] 97 a1 [2] 91 94 [2] bf 94 [2] 80 88 }

  condition:
    any of them
}