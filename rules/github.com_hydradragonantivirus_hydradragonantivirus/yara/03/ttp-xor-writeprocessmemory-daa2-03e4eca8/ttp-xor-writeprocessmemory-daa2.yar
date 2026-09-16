rule TTP_XOR_WriteProcessMemory_daa2 {
  strings:
    $key_daa2 = { 8d d0 [2] bf f2 [2] b9 c7 [2] 97 c7 [2] a8 db }

  condition:
    any of them
}