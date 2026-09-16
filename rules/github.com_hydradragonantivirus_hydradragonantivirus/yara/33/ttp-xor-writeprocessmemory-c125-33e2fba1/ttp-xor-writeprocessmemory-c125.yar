rule TTP_XOR_WriteProcessMemory_c125 {
  strings:
    $key_c125 = { 96 57 [2] a4 75 [2] a2 40 [2] 8c 40 [2] b3 5c }

  condition:
    any of them
}