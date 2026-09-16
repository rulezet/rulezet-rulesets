rule TTP_XOR_WriteProcessMemory_65a2 {
  strings:
    $key_65a2 = { 32 d0 [2] 00 f2 [2] 06 c7 [2] 28 c7 [2] 17 db }

  condition:
    any of them
}