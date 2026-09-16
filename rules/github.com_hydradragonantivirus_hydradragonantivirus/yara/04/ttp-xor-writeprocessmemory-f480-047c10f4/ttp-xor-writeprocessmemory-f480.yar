rule TTP_XOR_WriteProcessMemory_f480 {
  strings:
    $key_f480 = { a3 f2 [2] 91 d0 [2] 97 e5 [2] b9 e5 [2] 86 f9 }

  condition:
    any of them
}