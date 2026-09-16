rule TTP_XOR_WriteProcessMemory_35a2 {
  strings:
    $key_35a2 = { 62 d0 [2] 50 f2 [2] 56 c7 [2] 78 c7 [2] 47 db }

  condition:
    any of them
}