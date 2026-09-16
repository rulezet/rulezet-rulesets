rule TTP_XOR_WriteProcessMemory_d5c7 {
  strings:
    $key_d5c7 = { 82 b5 [2] b0 97 [2] b6 a2 [2] 98 a2 [2] a7 be }

  condition:
    any of them
}