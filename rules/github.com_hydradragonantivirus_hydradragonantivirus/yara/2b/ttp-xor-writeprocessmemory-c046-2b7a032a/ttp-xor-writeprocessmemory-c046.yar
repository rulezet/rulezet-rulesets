rule TTP_XOR_WriteProcessMemory_c046 {
  strings:
    $key_c046 = { 97 34 [2] a5 16 [2] a3 23 [2] 8d 23 [2] b2 3f }

  condition:
    any of them
}