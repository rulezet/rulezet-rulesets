rule TTP_XOR_WriteProcessMemory_d605 {
  strings:
    $key_d605 = { 81 77 [2] b3 55 [2] b5 60 [2] 9b 60 [2] a4 7c }

  condition:
    any of them
}