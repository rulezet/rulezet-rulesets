rule TTP_XOR_WriteProcessMemory_d445 {
  strings:
    $key_d445 = { 83 37 [2] b1 15 [2] b7 20 [2] 99 20 [2] a6 3c }

  condition:
    any of them
}