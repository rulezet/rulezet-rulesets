rule TTP_XOR_WriteProcessMemory_d145 {
  strings:
    $key_d145 = { 86 37 [2] b4 15 [2] b2 20 [2] 9c 20 [2] a3 3c }

  condition:
    any of them
}