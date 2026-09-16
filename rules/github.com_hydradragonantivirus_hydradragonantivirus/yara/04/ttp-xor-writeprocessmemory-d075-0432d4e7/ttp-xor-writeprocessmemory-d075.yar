rule TTP_XOR_WriteProcessMemory_d075 {
  strings:
    $key_d075 = { 87 07 [2] b5 25 [2] b3 10 [2] 9d 10 [2] a2 0c }

  condition:
    any of them
}