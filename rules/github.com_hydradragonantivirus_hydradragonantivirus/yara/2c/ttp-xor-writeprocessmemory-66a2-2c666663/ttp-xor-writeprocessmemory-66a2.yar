rule TTP_XOR_WriteProcessMemory_66a2 {
  strings:
    $key_66a2 = { 31 d0 [2] 03 f2 [2] 05 c7 [2] 2b c7 [2] 14 db }

  condition:
    any of them
}