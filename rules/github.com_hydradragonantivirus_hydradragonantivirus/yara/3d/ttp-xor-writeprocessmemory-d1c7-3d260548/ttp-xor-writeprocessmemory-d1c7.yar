rule TTP_XOR_WriteProcessMemory_d1c7 {
  strings:
    $key_d1c7 = { 86 b5 [2] b4 97 [2] b2 a2 [2] 9c a2 [2] a3 be }

  condition:
    any of them
}