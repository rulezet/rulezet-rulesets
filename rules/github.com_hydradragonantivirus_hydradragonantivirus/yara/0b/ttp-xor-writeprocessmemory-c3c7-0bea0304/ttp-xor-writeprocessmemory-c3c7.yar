rule TTP_XOR_WriteProcessMemory_c3c7 {
  strings:
    $key_c3c7 = { 94 b5 [2] a6 97 [2] a0 a2 [2] 8e a2 [2] b1 be }

  condition:
    any of them
}