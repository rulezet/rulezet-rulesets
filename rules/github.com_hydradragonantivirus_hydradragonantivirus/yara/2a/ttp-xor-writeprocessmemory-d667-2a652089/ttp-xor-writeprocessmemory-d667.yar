rule TTP_XOR_WriteProcessMemory_d667 {
  strings:
    $key_d667 = { 81 15 [2] b3 37 [2] b5 02 [2] 9b 02 [2] a4 1e }

  condition:
    any of them
}