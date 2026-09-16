rule TTP_XOR_WriteProcessMemory_c7e5 {
  strings:
    $key_c7e5 = { 90 97 [2] a2 b5 [2] a4 80 [2] 8a 80 [2] b5 9c }

  condition:
    any of them
}