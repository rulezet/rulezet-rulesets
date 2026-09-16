rule TTP_XOR_WriteProcessMemory_f3e5 {
  strings:
    $key_f3e5 = { a4 97 [2] 96 b5 [2] 90 80 [2] be 80 [2] 81 9c }

  condition:
    any of them
}