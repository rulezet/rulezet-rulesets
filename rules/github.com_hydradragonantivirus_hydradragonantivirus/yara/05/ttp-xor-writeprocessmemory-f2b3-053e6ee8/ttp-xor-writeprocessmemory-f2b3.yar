rule TTP_XOR_WriteProcessMemory_f2b3 {
  strings:
    $key_f2b3 = { a5 c1 [2] 97 e3 [2] 91 d6 [2] bf d6 [2] 80 ca }

  condition:
    any of them
}