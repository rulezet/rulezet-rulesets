rule TTP_XOR_WriteProcessMemory_c0d0 {
  strings:
    $key_c0d0 = { 97 a2 [2] a5 80 [2] a3 b5 [2] 8d b5 [2] b2 a9 }

  condition:
    any of them
}