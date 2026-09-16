rule TTP_XOR_WriteProcessMemory_23a2 {
  strings:
    $key_23a2 = { 74 d0 [2] 46 f2 [2] 40 c7 [2] 6e c7 [2] 51 db }

  condition:
    any of them
}