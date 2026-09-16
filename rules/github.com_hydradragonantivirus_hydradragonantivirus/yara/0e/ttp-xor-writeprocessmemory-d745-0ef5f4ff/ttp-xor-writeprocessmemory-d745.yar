rule TTP_XOR_WriteProcessMemory_d745 {
  strings:
    $key_d745 = { 80 37 [2] b2 15 [2] b4 20 [2] 9a 20 [2] a5 3c }

  condition:
    any of them
}