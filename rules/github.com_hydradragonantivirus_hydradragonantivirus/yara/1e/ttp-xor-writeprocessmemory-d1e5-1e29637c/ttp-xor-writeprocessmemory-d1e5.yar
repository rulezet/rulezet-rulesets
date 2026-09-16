rule TTP_XOR_WriteProcessMemory_d1e5 {
  strings:
    $key_d1e5 = { 86 97 [2] b4 b5 [2] b2 80 [2] 9c 80 [2] a3 9c }

  condition:
    any of them
}