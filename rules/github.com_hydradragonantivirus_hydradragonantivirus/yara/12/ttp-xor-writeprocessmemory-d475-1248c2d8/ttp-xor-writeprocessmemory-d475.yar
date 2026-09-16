rule TTP_XOR_WriteProcessMemory_d475 {
  strings:
    $key_d475 = { 83 07 [2] b1 25 [2] b7 10 [2] 99 10 [2] a6 0c }

  condition:
    any of them
}