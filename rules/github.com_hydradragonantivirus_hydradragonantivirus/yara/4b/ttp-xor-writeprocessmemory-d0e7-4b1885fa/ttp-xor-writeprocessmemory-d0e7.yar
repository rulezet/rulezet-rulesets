rule TTP_XOR_WriteProcessMemory_d0e7 {
  strings:
    $key_d0e7 = { 87 95 [2] b5 b7 [2] b3 82 [2] 9d 82 [2] a2 9e }

  condition:
    any of them
}