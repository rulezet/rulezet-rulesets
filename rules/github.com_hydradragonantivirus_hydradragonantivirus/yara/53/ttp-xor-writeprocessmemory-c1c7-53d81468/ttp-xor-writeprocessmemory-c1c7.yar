rule TTP_XOR_WriteProcessMemory_c1c7 {
  strings:
    $key_c1c7 = { 96 b5 [2] a4 97 [2] a2 a2 [2] 8c a2 [2] b3 be }

  condition:
    any of them
}