rule TTP_XOR_WriteProcessMemory_c445 {
  strings:
    $key_c445 = { 93 37 [2] a1 15 [2] a7 20 [2] 89 20 [2] b6 3c }

  condition:
    any of them
}