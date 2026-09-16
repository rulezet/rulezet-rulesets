rule TTP_XOR_WriteProcessMemory_f4f5 {
  strings:
    $key_f4f5 = { a3 87 [2] 91 a5 [2] 97 90 [2] b9 90 [2] 86 8c }

  condition:
    any of them
}