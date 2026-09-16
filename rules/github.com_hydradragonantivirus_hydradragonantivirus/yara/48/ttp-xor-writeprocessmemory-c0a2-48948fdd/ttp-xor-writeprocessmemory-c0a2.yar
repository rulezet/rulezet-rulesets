rule TTP_XOR_WriteProcessMemory_c0a2 {
  strings:
    $key_c0a2 = { 97 d0 [2] a5 f2 [2] a3 c7 [2] 8d c7 [2] b2 db }

  condition:
    any of them
}