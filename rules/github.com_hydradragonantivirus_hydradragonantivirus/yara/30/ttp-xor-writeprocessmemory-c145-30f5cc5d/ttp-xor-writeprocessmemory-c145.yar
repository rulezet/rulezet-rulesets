rule TTP_XOR_WriteProcessMemory_c145 {
  strings:
    $key_c145 = { 96 37 [2] a4 15 [2] a2 20 [2] 8c 20 [2] b3 3c }

  condition:
    any of them
}