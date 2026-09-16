rule TTP_XOR_WriteProcessMemory_c765 {
  strings:
    $key_c765 = { 90 17 [2] a2 35 [2] a4 00 [2] 8a 00 [2] b5 1c }

  condition:
    any of them
}