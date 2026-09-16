rule TTP_XOR_WriteProcessMemory_75a2 {
  strings:
    $key_75a2 = { 22 d0 [2] 10 f2 [2] 16 c7 [2] 38 c7 [2] 07 db }

  condition:
    any of them
}