rule TTP_XOR_WriteProcessMemory_e4a2 {
  strings:
    $key_e4a2 = { b3 d0 [2] 81 f2 [2] 87 c7 [2] a9 c7 [2] 96 db }

  condition:
    any of them
}