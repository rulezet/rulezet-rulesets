rule TTP_XOR_WriteProcessMemory_f4d2 {
  strings:
    $key_f4d2 = { a3 a0 [2] 91 82 [2] 97 b7 [2] b9 b7 [2] 86 ab }

  condition:
    any of them
}