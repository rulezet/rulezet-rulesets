rule TTP_XOR_WriteProcessMemory_c091 {
  strings:
    $key_c091 = { 97 e3 [2] a5 c1 [2] a3 f4 [2] 8d f4 [2] b2 e8 }

  condition:
    any of them
}