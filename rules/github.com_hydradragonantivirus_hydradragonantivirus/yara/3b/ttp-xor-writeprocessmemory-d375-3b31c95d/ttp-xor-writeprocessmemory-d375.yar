rule TTP_XOR_WriteProcessMemory_d375 {
  strings:
    $key_d375 = { 84 07 [2] b6 25 [2] b0 10 [2] 9e 10 [2] a1 0c }

  condition:
    any of them
}