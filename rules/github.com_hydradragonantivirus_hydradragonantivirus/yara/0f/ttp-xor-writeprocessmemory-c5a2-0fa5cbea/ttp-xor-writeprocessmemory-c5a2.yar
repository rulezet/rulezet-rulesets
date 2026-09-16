rule TTP_XOR_WriteProcessMemory_c5a2 {
  strings:
    $key_c5a2 = { 92 d0 [2] a0 f2 [2] a6 c7 [2] 88 c7 [2] b7 db }

  condition:
    any of them
}