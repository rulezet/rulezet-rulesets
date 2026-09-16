rule TTP_XOR_WriteProcessMemory_d405 {
  strings:
    $key_d405 = { 83 77 [2] b1 55 [2] b7 60 [2] 99 60 [2] a6 7c }

  condition:
    any of them
}