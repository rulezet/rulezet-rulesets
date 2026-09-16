rule TTP_XOR_WriteProcessMemory_d7e7 {
  strings:
    $key_d7e7 = { 80 95 [2] b2 b7 [2] b4 82 [2] 9a 82 [2] a5 9e }

  condition:
    any of them
}