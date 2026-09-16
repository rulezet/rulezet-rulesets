rule TTP_XOR_WriteProcessMemory_40a2 {
  strings:
    $key_40a2 = { 17 d0 [2] 25 f2 [2] 23 c7 [2] 0d c7 [2] 32 db }

  condition:
    any of them
}