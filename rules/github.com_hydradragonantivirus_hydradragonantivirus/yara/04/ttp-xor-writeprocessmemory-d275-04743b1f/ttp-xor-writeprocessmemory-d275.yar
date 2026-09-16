rule TTP_XOR_WriteProcessMemory_d275 {
  strings:
    $key_d275 = { 85 07 [2] b7 25 [2] b1 10 [2] 9f 10 [2] a0 0c }

  condition:
    any of them
}