rule TTP_XOR_WriteProcessMemory_d1b5 {
  strings:
    $key_d1b5 = { 86 c7 [2] b4 e5 [2] b2 d0 [2] 9c d0 [2] a3 cc }

  condition:
    any of them
}