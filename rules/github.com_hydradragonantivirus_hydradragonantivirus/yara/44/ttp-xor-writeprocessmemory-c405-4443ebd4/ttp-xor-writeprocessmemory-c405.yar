rule TTP_XOR_WriteProcessMemory_c405 {
  strings:
    $key_c405 = { 93 77 [2] a1 55 [2] a7 60 [2] 89 60 [2] b6 7c }

  condition:
    any of them
}