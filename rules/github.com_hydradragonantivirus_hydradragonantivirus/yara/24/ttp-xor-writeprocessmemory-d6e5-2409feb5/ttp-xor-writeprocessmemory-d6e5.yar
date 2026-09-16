rule TTP_XOR_WriteProcessMemory_d6e5 {
  strings:
    $key_d6e5 = { 81 97 [2] b3 b5 [2] b5 80 [2] 9b 80 [2] a4 9c }

  condition:
    any of them
}