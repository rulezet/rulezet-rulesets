rule TTP_XOR_WriteProcessMemory_f2a8 {
  strings:
    $key_f2a8 = { a5 da [2] 97 f8 [2] 91 cd [2] bf cd [2] 80 d1 }

  condition:
    any of them
}