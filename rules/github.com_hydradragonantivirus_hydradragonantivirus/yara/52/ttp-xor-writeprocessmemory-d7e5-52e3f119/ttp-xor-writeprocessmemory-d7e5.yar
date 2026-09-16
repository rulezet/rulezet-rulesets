rule TTP_XOR_WriteProcessMemory_d7e5 {
  strings:
    $key_d7e5 = { 80 97 [2] b2 b5 [2] b4 80 [2] 9a 80 [2] a5 9c }

  condition:
    any of them
}