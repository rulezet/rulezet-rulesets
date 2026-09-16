rule TTP_XOR_WriteProcessMemory_d625 {
  strings:
    $key_d625 = { 81 57 [2] b3 75 [2] b5 40 [2] 9b 40 [2] a4 5c }

  condition:
    any of them
}