rule TTP_XOR_WriteProcessMemory_f375 {
  strings:
    $key_f375 = { a4 07 [2] 96 25 [2] 90 10 [2] be 10 [2] 81 0c }

  condition:
    any of them
}