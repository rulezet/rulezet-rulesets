rule TTP_XOR_WriteProcessMemory_f250 {
  strings:
    $key_f250 = { a5 22 [2] 97 00 [2] 91 35 [2] bf 35 [2] 80 29 }

  condition:
    any of them
}