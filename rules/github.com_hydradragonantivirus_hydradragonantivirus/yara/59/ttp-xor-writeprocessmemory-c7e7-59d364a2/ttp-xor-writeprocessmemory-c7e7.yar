rule TTP_XOR_WriteProcessMemory_c7e7 {
  strings:
    $key_c7e7 = { 90 95 [2] a2 b7 [2] a4 82 [2] 8a 82 [2] b5 9e }

  condition:
    any of them
}