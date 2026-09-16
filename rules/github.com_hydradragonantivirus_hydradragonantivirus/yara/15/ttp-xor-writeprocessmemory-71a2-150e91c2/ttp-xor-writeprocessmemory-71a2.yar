rule TTP_XOR_WriteProcessMemory_71a2 {
  strings:
    $key_71a2 = { 26 d0 [2] 14 f2 [2] 12 c7 [2] 3c c7 [2] 03 db }

  condition:
    any of them
}