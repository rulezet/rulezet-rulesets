rule TTP_XOR_WriteProcessMemory_d7a2 {
  strings:
    $key_d7a2 = { 80 d0 [2] b2 f2 [2] b4 c7 [2] 9a c7 [2] a5 db }

  condition:
    any of them
}