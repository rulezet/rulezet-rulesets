rule TTP_XOR_WriteProcessMemory_f425 {
  strings:
    $key_f425 = { a3 57 [2] 91 75 [2] 97 40 [2] b9 40 [2] 86 5c }

  condition:
    any of them
}