rule TTP_XOR_WriteProcessMemory_d0a2 {
  strings:
    $key_d0a2 = { 87 d0 [2] b5 f2 [2] b3 c7 [2] 9d c7 [2] a2 db }

  condition:
    any of them
}