rule TTP_XOR_WriteProcessMemory_77a2 {
  strings:
    $key_77a2 = { 20 d0 [2] 12 f2 [2] 14 c7 [2] 3a c7 [2] 05 db }

  condition:
    any of them
}