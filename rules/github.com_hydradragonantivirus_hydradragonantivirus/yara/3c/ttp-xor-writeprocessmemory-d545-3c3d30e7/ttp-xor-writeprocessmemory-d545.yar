rule TTP_XOR_WriteProcessMemory_d545 {
  strings:
    $key_d545 = { 82 37 [2] b0 15 [2] b6 20 [2] 98 20 [2] a7 3c }

  condition:
    any of them
}