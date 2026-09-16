rule TTP_XOR_WriteProcessMemory_56a2 {
  strings:
    $key_56a2 = { 01 d0 [2] 33 f2 [2] 35 c7 [2] 1b c7 [2] 24 db }

  condition:
    any of them
}