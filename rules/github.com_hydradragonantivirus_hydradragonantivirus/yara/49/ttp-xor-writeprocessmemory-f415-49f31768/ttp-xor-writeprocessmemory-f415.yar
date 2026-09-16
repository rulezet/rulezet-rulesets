rule TTP_XOR_WriteProcessMemory_f415 {
  strings:
    $key_f415 = { a3 67 [2] 91 45 [2] 97 70 [2] b9 70 [2] 86 6c }

  condition:
    any of them
}