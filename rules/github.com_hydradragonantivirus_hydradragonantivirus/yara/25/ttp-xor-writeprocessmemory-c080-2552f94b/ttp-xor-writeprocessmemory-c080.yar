rule TTP_XOR_WriteProcessMemory_c080 {
  strings:
    $key_c080 = { 97 f2 [2] a5 d0 [2] a3 e5 [2] 8d e5 [2] b2 f9 }

  condition:
    any of them
}