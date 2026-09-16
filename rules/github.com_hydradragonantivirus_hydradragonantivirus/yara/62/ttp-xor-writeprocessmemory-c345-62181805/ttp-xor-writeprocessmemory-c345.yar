rule TTP_XOR_WriteProcessMemory_c345 {
  strings:
    $key_c345 = { 94 37 [2] a6 15 [2] a0 20 [2] 8e 20 [2] b1 3c }

  condition:
    any of them
}