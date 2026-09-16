rule TTP_XOR_WriteProcessMemory_01a2 {
  strings:
    $key_01a2 = { 56 d0 [2] 64 f2 [2] 62 c7 [2] 4c c7 [2] 73 db }

  condition:
    any of them
}