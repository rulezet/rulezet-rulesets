rule TTP_XOR_WriteProcessMemory_c6e7 {
  strings:
    $key_c6e7 = { 91 95 [2] a3 b7 [2] a5 82 [2] 8b 82 [2] b4 9e }

  condition:
    any of them
}