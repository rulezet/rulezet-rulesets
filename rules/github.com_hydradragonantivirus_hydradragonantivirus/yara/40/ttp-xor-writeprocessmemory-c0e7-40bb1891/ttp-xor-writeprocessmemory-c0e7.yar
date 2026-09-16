rule TTP_XOR_WriteProcessMemory_c0e7 {
  strings:
    $key_c0e7 = { 97 95 [2] a5 b7 [2] a3 82 [2] 8d 82 [2] b2 9e }

  condition:
    any of them
}